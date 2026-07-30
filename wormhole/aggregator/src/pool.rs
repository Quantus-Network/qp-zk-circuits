//! Proof pool for delegated (public-batch) aggregation.
//!
//! A miner-facing, in-memory pool of private-batch proofs received from
//! untrusted clients. Proofs are cryptographically verified on admission and
//! bucketed by the metadata the public-batch circuit constrains across a batch
//! (block hash, asset id, volume fee), so every bucket is aggregatable by
//! construction: the "when to aggregate which bucket" decision is left to the
//! operator's policy, fed by [`BucketStats`].
//!
//! # Custody: the pool may be a proof's only holder
//!
//! A miner runs this pool over proofs pulled from the node's transaction pool
//! or intercepted from gossip before it — and a miner aggregating a proof for
//! the reward has every incentive NOT to relay it further (it is claiming the
//! proof for its own batch). A pooled proof must therefore be treated as
//! possibly existing nowhere else in the network until it settles, so the
//! pool never gives up custody for proving:
//!
//! [`ProofPool::snapshot_batch`] CLONES the oldest `batch_size` proofs of a
//! bucket; the originals stay pooled. Prove the snapshot without holding any
//! pool lock (public-batch proving is tens of seconds, i.e. a few block
//! times), submit the result, and let the on-chain settlement retire the
//! proved inputs through the regular [`ProofPool::evict_settled`] cadence. A
//! failed or crashed proving attempt needs no recovery protocol: the pool
//! never changed. The paths that remove a proof are settlement eviction,
//! expiry ([`ProofPool::evict_older_than`]), and the explicit operator
//! override [`ProofPool::remove_bucket`].
//!
//! Buckets queue arbitrarily deep (bounded only by [`PoolLimits`]), so a hot
//! (block, asset, fee) stream keeps admitting while earlier batches are being
//! proved.
//!
//! Staleness: a queued proof becomes worthless once any of its nullifiers is
//! settled on-chain (e.g. another miner included the same private batch, or a
//! public batch containing it — including this miner's own submissions).
//! Operators should call [`ProofPool::evict_settled`] with newly settled
//! nullifiers on every imported block — both before proving (don't aggregate
//! dead weight) and before submitting a finished public batch (don't submit
//! stale segments). Until a submitted batch settles, its bucket remains
//! snapshot-able; use [`BucketStats::last_snapshot_age`] to skip buckets with
//! a submission plausibly still in flight instead of re-proving them every
//! policy cycle (a full public-batch prove is tens of seconds of CPU).
//!
//! Expiry: settlement is the only AUTOMATIC drain, and it only ever sees
//! nullifiers that reach the chain. A proof that never settles — its miner
//! lost the inclusion race and the referenced block fell out of the pallet's
//! acceptance window — would otherwise stay resident forever, permanently
//! consuming [`PoolLimits::max_proofs`] (which is the whole memory bound).
//! Operators MUST therefore run an expiry policy: either call
//! [`ProofPool::evict_older_than`] on a cadence with an age comfortably past
//! the chain's acceptance window, or implement their own via
//! [`ProofPool::remove_bucket`].
//!
//! Note on nullifier checks: the pool-wide duplicate-nullifier rejection at
//! admission and `evict_settled` are OPERATIONAL, not security-critical. They
//! keep the miner from wasting proving time on batches the chain would refuse
//! and prevent duplicate-based capacity DoS. The actual double-spend boundary
//! is the wormhole pallet's persistent settled-nullifier set, which settles
//! each nullifier at most once regardless of what any aggregator pools or
//! submits. See "Nullifiers and Double-Spend Prevention" in
//! `wormhole/README.md`.
//!
//! Note on dummies: an all-dummy private-batch proof (all-zero block hash) is
//! REJECTED at admission even though it can be cryptographically valid. It
//! settles nothing and only expiry could ever reclaim it (aggregating it is
//! refused, and `evict_settled` never sees its random nullifiers on-chain),
//! so pooling it would let an attacker occupy global capacity with dead
//! entries for a full expiry window at a time. Public-batch padding does
//! not need pooled dummies either: the prover pads from its own pinned dummy
//! template.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Result};
use plonky2::field::types::PrimeField64;
use plonky2::plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs};
use qp_wormhole_inputs::{validate_proof_count, BytesDigest};
use zk_circuits_common::{
    circuit::{C, D, F},
    utils::try_4_felts_to_bytes,
};

use crate::private_batch::circuit::constants::aggregated_output;

type Proof = ProofWithPublicInputs<F, C, D>;

/// The metadata the public-batch circuit requires all non-dummy inner proofs in
/// one batch to share. Proofs with equal keys are aggregatable together by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchKey {
    pub block_hash: BytesDigest,
    pub asset_id: u64,
    pub volume_fee_bps: u64,
}

impl BatchKey {
    /// All-dummy sentinel: the proof references no real block and settles nothing.
    pub fn is_dummy(&self) -> bool {
        self.block_hash == BytesDigest::default()
    }
}

/// Global size limits protecting a pool that fronts untrusted traffic.
#[derive(Debug, Clone, Copy)]
pub struct PoolLimits {
    /// Maximum number of proofs the pool retains across all buckets.
    ///
    /// Proving is non-consuming ([`ProofPool::snapshot_batch`] clones, the
    /// originals stay resident), so this is the whole memory bound: there is
    /// no out-for-proving state to account for separately.
    pub max_proofs: usize,
    /// Maximum number of distinct buckets (keys).
    pub max_buckets: usize,
    /// Maximum cryptographic verification ATTEMPTS per [`Self::verify_window`].
    ///
    /// Size caps alone don't bound admission CPU: invalid proofs are rejected
    /// by verification and never consume a slot, so an attacker streaming
    /// well-formed-but-invalid proofs (fresh random nullifiers, correct PI
    /// shape) would reach the expensive recursive verify on every submission.
    /// This budget counts every verification attempt — successful or not — and
    /// [`ProofPool::push`] rejects cheaply once it is exhausted, bounding
    /// worst-case verification CPU regardless of traffic.
    ///
    /// This is a global, identity-blind backstop: a flooding attacker can
    /// exhaust the budget and delay honest admissions (they cannot touch
    /// already-pooled proofs or proving). Per-client fairness needs rate
    /// limiting or authentication at the transport layer, where client
    /// identity exists.
    pub max_verifies_per_window: usize,
    /// Length of the verification budget window.
    pub verify_window: Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_proofs: 1024,
            max_buckets: 256,
            // ~2.5-5s of verification CPU per minute at worst (recursive
            // verification is ~10-20ms) while far exceeding honest submission
            // rates (256 private batches/minute).
            max_verifies_per_window: 256,
            verify_window: Duration::from_secs(60),
        }
    }
}

/// Point-in-time view of one bucket, for the operator's aggregation policy.
#[derive(Debug, Clone)]
pub struct BucketStats {
    pub key: BatchKey,
    /// Number of proofs currently queued in this bucket. Buckets queue
    /// arbitrarily deep (bounded only by [`PoolLimits`]), so this can exceed
    /// `batch_size`.
    pub num_proofs: usize,
    /// Public-batch size: how many proofs one [`ProofPool::snapshot_batch`]
    /// clones, and the count at which a batch aggregates without dummy
    /// padding.
    pub batch_size: usize,
    /// Time since the oldest queued proof in this bucket was admitted.
    ///
    /// This is also the expiry signal: a bucket whose oldest proof predates
    /// the chain's acceptance window for its block can never settle and only
    /// [`ProofPool::evict_older_than`] / [`ProofPool::remove_bucket`] will
    /// reclaim its capacity.
    pub oldest_age: Duration,
    /// Sum of all exit-slot amounts across queued proofs (settled volume proxy).
    pub total_volume: u64,
    /// Time since this bucket was last snapshot via
    /// [`ProofPool::snapshot_batch`], or `None` if it never was.
    ///
    /// Proving is non-consuming, so a bucket whose batch is submitted but not
    /// yet settled looks exactly like an untouched one — except for this
    /// field. A policy loop should treat a recent snapshot as "submission in
    /// flight" and skip the bucket until it settles (evicting the proofs) or
    /// the operator's re-prove timeout passes, rather than re-proving the
    /// same batch every cycle.
    pub last_snapshot_age: Option<Duration>,
}

impl BucketStats {
    /// Whether the bucket holds at least one full (padding-free) batch.
    pub fn is_full(&self) -> bool {
        self.num_proofs >= self.batch_size
    }

    /// Whether this is the dummy sentinel bucket (`block_hash == 0`).
    /// Should never be true — [`ProofPool::push`] rejects all-dummy proofs —
    /// but kept so policy code can defend in depth.
    pub fn is_dummy(&self) -> bool {
        self.key.is_dummy()
    }
}

#[derive(Debug)]
struct PooledProof {
    proof: Proof,
    nullifiers: Vec<BytesDigest>,
    volume: u64,
    admitted_at: Instant,
}

#[derive(Debug, Default)]
struct Bucket {
    proofs: Vec<PooledProof>,
    /// When this bucket was last snapshot for proving (surfaced as
    /// [`BucketStats::last_snapshot_age`], the policy layer's in-flight signal).
    last_snapshot_at: Option<Instant>,
}

/// A bounded pool of admission-verified private-batch proofs, bucketed by
/// [`BatchKey`].
#[derive(Debug)]
pub struct ProofPool {
    /// Canonical-pinned private-batch verifier data used for admission.
    verifier: VerifierCircuitData<F, C, D>,
    /// Leaves per inner private-batch proof (fixes the PI layout).
    inner_num_leaves: usize,
    /// Proofs per bucket (= public-batch size).
    batch_size: usize,
    limits: PoolLimits,
    buckets: BTreeMap<BatchKey, Bucket>,
    /// Global index of every pooled nullifier to the bucket holding its proof.
    ///
    /// Duplicates are rejected pool-wide, not just per bucket: the merkle tree
    /// is cumulative, so the SAME spend can be validly proven against two
    /// different recent blocks, landing in different buckets — only one copy
    /// can ever settle. The index also makes [`Self::evict_settled`] a lookup
    /// instead of a full pool scan. Invariant: contains exactly the nullifiers
    /// of proofs currently in `buckets` (proving is non-consuming, so proofs
    /// being proved are still in `buckets` and need no separate tracking).
    nullifier_index: HashMap<BytesDigest, BatchKey>,
    /// Start of the current verification budget window (fixed-window counter).
    verify_window_started: Instant,
    /// Verification attempts (successful or not) in the current window.
    verifies_in_window: usize,
}

impl ProofPool {
    /// Create a pool admitting proofs valid under `verifier`.
    ///
    /// `inner_num_leaves` is the number of leaves aggregated per private-batch
    /// proof and `batch_size` the number of private-batch proofs per public
    /// batch; both must match the circuit shapes pinned into `verifier` and the
    /// public-batch prover this pool feeds. Both are per-layer proof counts and
    /// are validated against `MAX_PROOF_COUNT` before any layout arithmetic,
    /// so callers can pass untrusted dimensions here.
    pub fn new(
        verifier: VerifierCircuitData<F, C, D>,
        inner_num_leaves: usize,
        batch_size: usize,
        limits: PoolLimits,
    ) -> Result<Self> {
        // Bound both counts before the layout helpers below: pi_len does
        // unchecked arithmetic that would wrap on astronomical counts, and the
        // repo invariant is that every externally supplied batch dimension is
        // checked with validate_proof_count before allocation or arithmetic.
        validate_proof_count(inner_num_leaves, "inner_num_leaves")?;
        validate_proof_count(batch_size, "batch_size")?;
        ensure!(
            limits.max_proofs >= batch_size,
            "max_proofs ({}) must allow at least one full batch ({})",
            limits.max_proofs,
            batch_size
        );
        ensure!(limits.max_buckets > 0, "max_buckets must be positive");
        ensure!(
            limits.max_verifies_per_window > 0,
            "max_verifies_per_window must be positive"
        );
        ensure!(
            !limits.verify_window.is_zero(),
            "verify_window must be positive"
        );
        let expected_pi_len = aggregated_output::pi_len(inner_num_leaves);
        ensure!(
            verifier.common.num_public_inputs == expected_pi_len,
            "verifier public-input length {} does not match private-batch layout for {} leaves ({})",
            verifier.common.num_public_inputs,
            inner_num_leaves,
            expected_pi_len
        );
        Ok(Self {
            verifier,
            inner_num_leaves,
            batch_size,
            limits,
            buckets: BTreeMap::new(),
            nullifier_index: HashMap::new(),
            verify_window_started: Instant::now(),
            verifies_in_window: 0,
        })
    }

    /// Total number of proofs across all buckets (proving is non-consuming,
    /// so this includes proofs currently being proved from a snapshot).
    pub fn len(&self) -> usize {
        self.buckets.values().map(|b| b.proofs.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Validate and admit a proof, returning the bucket key it landed in.
    ///
    /// Checks run cheapest-first EXCEPT the pool-state membership tests:
    /// capacity limits, public-input shape, dummy sentinel, the verification
    /// budget ([`PoolLimits::max_verifies_per_window`]), cryptographic
    /// verification, and only THEN the bucket-cap and duplicate-nullifier
    /// checks. Both are deliberately gated behind verification so their
    /// rejections cannot be used as a free, unlimited membership/status
    /// oracle over the pool's not-yet-settled buckets or spends (see each
    /// check site). A proof admitted here is individually valid and, by
    /// bucketing, batch-compatible with every other proof in its bucket, so
    /// aggregation over a bucket cannot fail deterministically on admitted
    /// inputs (#97067).
    ///
    /// Buckets are NOT capped at one batch: a hot key keeps admitting (up to
    /// the global limits) while earlier batches for it are being proved;
    /// [`Self::snapshot_batch`] clones the oldest `batch_size` proofs at a
    /// time.
    pub fn push(&mut self, proof: Proof) -> Result<BatchKey> {
        if self.len() >= self.limits.max_proofs {
            bail!(
                "proof pool is full ({} proofs, limit {})",
                self.len(),
                self.limits.max_proofs
            );
        }

        let metadata = self.parse_metadata(&proof)?;
        let key = metadata.0;

        // Reject the all-dummy sentinel outright: it settles nothing and only
        // expiry could ever remove it (aggregation refuses the dummy bucket
        // and its random nullifiers never settle on-chain), so admitting it
        // would hand attackers a global-capacity sink lasting a full expiry
        // window per submission.
        if key.is_dummy() {
            bail!(
                "refusing to pool an all-dummy private-batch proof (block_hash == 0): \
                 it settles nothing, so settlement eviction can never drain it"
            );
        }

        // Verification budget: size caps only count ADMITTED proofs, and
        // invalid submissions never consume a slot, so without this an
        // attacker streaming well-formed-but-invalid proofs would buy a full
        // recursive verification per submission indefinitely. Charge the
        // budget before verifying (attempts, not successes, cost CPU).
        let now = Instant::now();
        if now.duration_since(self.verify_window_started) >= self.limits.verify_window {
            self.verify_window_started = now;
            self.verifies_in_window = 0;
        }
        if self.verifies_in_window >= self.limits.max_verifies_per_window {
            bail!(
                "proof admission verification budget exhausted ({} attempts in the current {:?} \
                 window); retry after the window resets",
                self.limits.max_verifies_per_window,
                self.limits.verify_window
            );
        }
        self.verifies_in_window += 1;

        self.verifier.verify(proof.clone()).map_err(|e| {
            anyhow!(
                "refusing to queue invalid private-batch proof: verification failed: {}",
                e
            )
        })?;

        // Bucket cap. Checked AFTER cryptographic verification and the verify
        // budget for the same reason as the duplicate-nullifier check below:
        // `buckets.contains_key(&key)` is a membership test over pool state
        // keyed by ATTACKER-CONTROLLED public inputs of the submitted proof.
        // Placed before verification (as a "cheapest-first" guard), a full
        // pool answered it for free — at max_buckets, a well-formed-but-
        // invalid probe carrying a candidate key was rejected instantly with
        // this distinct error when the key was novel, but fell through to
        // verification when the key was pooled, letting anyone enumerate
        // which (block, asset, fee) tuples the miner is aggregating without
        // holding a single valid proof (audit finding). Gated behind verify,
        // the probe requires a cryptographically valid private-batch proof
        // for the candidate key, and its cost is charged to the verify
        // budget like any other admission attempt. The cap itself is
        // operational (bounds bucket-map growth), not a CPU guard, so
        // nothing is lost by paying verification first.
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.limits.max_buckets {
            bail!(
                "proof pool bucket limit reached ({} buckets); proof rejected",
                self.limits.max_buckets
            );
        }

        // A duplicate nullifier anywhere in the pool means the same leaf
        // spend is already staged; only one copy can ever settle. This is
        // checked pool-wide (not per bucket): the cumulative merkle tree lets
        // the same spend be proven against different recent blocks, i.e. into
        // different buckets. It also deduplicates client re-submissions.
        //
        // Checked AFTER cryptographic verification and the verify budget, and
        // with a generic message: otherwise this rejection is a free,
        // unlimited membership oracle over the pool's not-yet-settled spends
        // — an attacker submitting invalid proofs that reuse an observed
        // nullifier could confirm the spend is pooled and learn which block
        // it referenced, all without paying verification cost. Gating it
        // behind verify means a probe now requires a cryptographically valid
        // proof carrying the target nullifier (i.e. actually holding that
        // spend), and the error reveals only that some nullifier collided,
        // not which one or from which bucket.
        if metadata
            .1
            .iter()
            .any(|n| self.nullifier_index.contains_key(n))
        {
            bail!(
                "refusing to queue private-batch proof: a nullifier in this proof \
                 is already staged in the pool"
            );
        }

        let (key, nullifiers, volume) = metadata;
        for nullifier in &nullifiers {
            self.nullifier_index.insert(*nullifier, key);
        }
        self.buckets
            .entry(key)
            .or_default()
            .proofs
            .push(PooledProof {
                proof,
                nullifiers,
                volume,
                admitted_at: Instant::now(),
            });
        Ok(key)
    }

    /// Remove every queued proof that has at least one nullifier in `settled`,
    /// dropping buckets that become empty. Returns the number of evicted proofs.
    ///
    /// Call with the nullifiers settled by each imported block, both before
    /// aggregating (avoid proving dead weight) and before submitting a finished
    /// public batch (detect batches that went stale mid-proving).
    ///
    /// Proving is non-consuming, so proofs currently being proved from a
    /// [`Self::snapshot_batch`] are still resident and are evicted here like
    /// any others. This is also what retires a bucket's proofs once this
    /// miner's own submitted public batch settles.
    pub fn evict_settled(&mut self, settled: &HashSet<BytesDigest>) -> usize {
        // The nullifier index turns this into a lookup over `settled` instead
        // of a scan of every pooled proof.
        let affected_keys: HashSet<BatchKey> = settled
            .iter()
            .filter_map(|n| self.nullifier_index.get(n).copied())
            .collect();

        let mut evicted = 0;
        for key in affected_keys {
            let Some(bucket) = self.buckets.get_mut(&key) else {
                continue;
            };
            bucket.proofs.retain(|queued| {
                let stale = queued.nullifiers.iter().any(|n| settled.contains(n));
                if stale {
                    evicted += 1;
                    for n in &queued.nullifiers {
                        self.nullifier_index.remove(n);
                    }
                }
                !stale
            });
            if bucket.proofs.is_empty() {
                self.buckets.remove(&key);
            }
        }
        evicted
    }

    /// Remove every queued proof admitted more than `max_age` ago, dropping
    /// buckets that become empty. Returns the number of evicted proofs.
    ///
    /// This is the expiry backstop settlement eviction cannot provide: a
    /// proof whose miner lost the inclusion race for its referenced block
    /// never has its nullifiers settle on-chain, so nothing else would ever
    /// reclaim its capacity — and [`PoolLimits::max_proofs`] is the whole
    /// memory bound. Operators MUST call this on a cadence (or run their own
    /// expiry via [`Self::remove_bucket`]) with a `max_age` comfortably past
    /// the chain's acceptance window for proof blocks, so only proofs that
    /// can no longer settle are dropped.
    ///
    /// Custody note: unlike [`Self::remove_bucket`], the expired proofs are
    /// dropped, not returned — past the acceptance window they are
    /// unsettleable on ANY chain, so there is no last-copy value to preserve.
    pub fn evict_older_than(&mut self, max_age: Duration) -> usize {
        let now = Instant::now();
        let mut evicted = 0;
        let nullifier_index = &mut self.nullifier_index;
        self.buckets.retain(|_, bucket| {
            bucket.proofs.retain(|queued| {
                let expired = now.saturating_duration_since(queued.admitted_at) > max_age;
                if expired {
                    evicted += 1;
                    for n in &queued.nullifiers {
                        nullifier_index.remove(n);
                    }
                }
                !expired
            });
            !bucket.proofs.is_empty()
        });
        evicted
    }

    /// Per-bucket statistics for the operator's aggregation policy.
    pub fn bucket_stats(&self) -> Vec<BucketStats> {
        let now = Instant::now();
        self.buckets
            .iter()
            .map(|(key, bucket)| BucketStats {
                key: *key,
                num_proofs: bucket.proofs.len(),
                batch_size: self.batch_size,
                oldest_age: bucket
                    .proofs
                    .iter()
                    .map(|q| now.saturating_duration_since(q.admitted_at))
                    .max()
                    .unwrap_or_default(),
                total_volume: bucket
                    .proofs
                    .iter()
                    .fold(0u64, |acc, q| acc.saturating_add(q.volume)),
                last_snapshot_age: bucket
                    .last_snapshot_at
                    .map(|at| now.saturating_duration_since(at)),
            })
            .collect()
    }

    /// Clone the oldest up-to-`batch_size` proofs of one bucket, for proving.
    /// Returns `None` if the bucket doesn't exist.
    ///
    /// NON-CONSUMING by design: a pooled proof may exist nowhere else in the
    /// network (a claiming miner withholds it from relay — see the module
    /// docs on custody), so the pool never gives up custody for proving.
    /// Prove the snapshot without holding any pool lock, submit the result,
    /// and let the on-chain settlement retire the proved inputs through
    /// [`Self::evict_settled`]. A failed or crashed proving attempt needs no
    /// cleanup: the pool never changed. Whether to re-prove a bucket whose
    /// batch is submitted but not yet settled is the caller's policy call —
    /// the snapshot time recorded here (surfaced as
    /// [`BucketStats::last_snapshot_age`]) is that policy's in-flight signal.
    ///
    /// Takes `&mut self` (to record the snapshot time), so whatever exclusive
    /// lock guards the pool also serializes concurrent snapshot attempts:
    /// two policy workers racing on the same key see each other's snapshot
    /// mark instead of both launching a duplicate ~tens-of-seconds prove.
    pub fn snapshot_batch(&mut self, key: &BatchKey) -> Option<Vec<Proof>> {
        let bucket = self.buckets.get_mut(key)?;
        let n = bucket.proofs.len().min(self.batch_size);
        bucket.last_snapshot_at = Some(Instant::now());
        Some(bucket.proofs[..n].iter().map(|q| q.proof.clone()).collect())
    }

    /// Remove one bucket entirely, returning its proofs (empty if absent).
    ///
    /// This is the operator override — the manual removal path besides
    /// settlement eviction and [`Self::evict_older_than`] — for buckets that
    /// will never be aggregated (e.g. a custom expiry policy). The returned
    /// proofs are the caller's responsibility; if they were claimed from
    /// gossip, dropping them here may drop the last copy in the network.
    pub fn remove_bucket(&mut self, key: &BatchKey) -> Vec<Proof> {
        self.buckets
            .remove(key)
            .map(|bucket| {
                bucket
                    .proofs
                    .into_iter()
                    .map(|q| {
                        for nullifier in &q.nullifiers {
                            self.nullifier_index.remove(nullifier);
                        }
                        q.proof
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse (key, nullifiers, volume) from a private-batch proof's public inputs.
    fn parse_metadata(&self, proof: &Proof) -> Result<(BatchKey, Vec<BytesDigest>, u64)> {
        let pis = &proof.public_inputs;
        let expected = self.verifier.common.num_public_inputs;
        if pis.len() != expected {
            bail!(
                "private-batch proof public input length mismatch: expected {}, got {}",
                expected,
                pis.len()
            );
        }

        let block_hash = try_4_felts_to_bytes(
            &pis[aggregated_output::BLOCK_HASH_OFFSET..aggregated_output::BLOCK_HASH_OFFSET + 4],
        )
        .map_err(|e| anyhow!("failed to parse private-batch proof block hash: {}", e))?;
        let key = BatchKey {
            block_hash,
            asset_id: pis[aggregated_output::ASSET_ID_OFFSET].to_canonical_u64(),
            volume_fee_bps: pis[aggregated_output::VOLUME_FEE_BPS_OFFSET].to_canonical_u64(),
        };

        let nullifiers_start = aggregated_output::nullifiers_start(self.inner_num_leaves);
        let nullifiers = (0..aggregated_output::nullifiers_count(self.inner_num_leaves))
            .map(|i| {
                let start = nullifiers_start + i * 4;
                try_4_felts_to_bytes(&pis[start..start + 4]).map_err(|e| {
                    anyhow!("failed to parse private-batch proof nullifier {}: {}", i, e)
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let exit_slots_start = aggregated_output::exit_slots_start();
        let volume = (0..aggregated_output::exit_slots_count(self.inner_num_leaves))
            .map(|i| {
                pis[exit_slots_start + i * aggregated_output::EXIT_SLOT_LEN].to_canonical_u64()
            })
            .fold(0u64, |acc, sum| acc.saturating_add(sum));

        Ok((key, nullifiers, volume))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    };

    const NUM_LEAVES: usize = 1;

    fn pi_len() -> usize {
        aggregated_output::pi_len(NUM_LEAVES)
    }

    /// A minimal circuit whose public inputs mimic the private-batch layout,
    /// so pool admission logic can be exercised without real aggregation proofs.
    fn build_fake_private_batch_circuit() -> (CircuitData<F, C, D>, Vec<Target>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let pis = builder.add_virtual_targets(pi_len());
        builder.range_check(pis[0], 32);
        builder.register_public_inputs(&pis);
        (builder.build::<C>(), pis)
    }

    struct FakePis {
        asset_id: u64,
        volume_fee_bps: u64,
        block: u64,
        exit_sums: [u64; 2],
        nullifier: u64,
    }

    fn prove_fake(data: &CircuitData<F, C, D>, targets: &[Target], p: &FakePis) -> Proof {
        let mut values = vec![F::ZERO; pi_len()];
        values[aggregated_output::NUM_EXIT_SLOTS_OFFSET] = F::from_canonical_u64(2);
        values[aggregated_output::ASSET_ID_OFFSET] = F::from_canonical_u64(p.asset_id);
        values[aggregated_output::VOLUME_FEE_BPS_OFFSET] = F::from_canonical_u64(p.volume_fee_bps);
        values[aggregated_output::BLOCK_HASH_OFFSET] = F::from_canonical_u64(p.block);
        for i in 0..2 {
            values[aggregated_output::exit_slots_start() + i * aggregated_output::EXIT_SLOT_LEN] =
                F::from_canonical_u64(p.exit_sums[i]);
        }
        values[aggregated_output::nullifiers_start(NUM_LEAVES)] =
            F::from_canonical_u64(p.nullifier);

        let mut pw = PartialWitness::new();
        for (t, v) in targets.iter().zip(values.iter()) {
            pw.set_target(*t, *v).unwrap();
        }
        data.prove(pw).unwrap()
    }

    fn nullifier_digest(n: u64) -> BytesDigest {
        let felts = [F::from_canonical_u64(n), F::ZERO, F::ZERO, F::ZERO];
        try_4_felts_to_bytes(&felts).unwrap()
    }

    fn make_pool(
        batch_size: usize,
        limits: PoolLimits,
    ) -> (ProofPool, CircuitData<F, C, D>, Vec<Target>) {
        let (data, targets) = build_fake_private_batch_circuit();
        let pool = ProofPool::new(data.verifier_data(), NUM_LEAVES, batch_size, limits).unwrap();
        (pool, data, targets)
    }

    fn fake(block: u64, nullifier: u64) -> FakePis {
        FakePis {
            asset_id: 0,
            volume_fee_bps: 10,
            block,
            exit_sums: [100, 50],
            nullifier,
        }
    }

    /// ProofPool::new is a public API and must bound caller-supplied batch
    /// dimensions BEFORE the layout arithmetic (pi_len is unchecked and would
    /// wrap on astronomical counts in release builds).
    #[test]
    fn new_rejects_out_of_range_dimensions() {
        use crate::private_batch::circuit::constants::LEAF_PI_LEN;
        use qp_wormhole_inputs::MAX_PROOF_COUNT;

        let (data, _) = build_fake_private_batch_circuit();

        for bad_leaves in [0, MAX_PROOF_COUNT + 1, usize::MAX / LEAF_PI_LEN + 1] {
            let err = ProofPool::new(data.verifier_data(), bad_leaves, 2, PoolLimits::default())
                .expect_err("out-of-range inner_num_leaves must be rejected");
            assert!(err.to_string().contains("inner_num_leaves"), "got: {err}");
        }
        for bad_batch in [0, MAX_PROOF_COUNT + 1] {
            let err = ProofPool::new(
                data.verifier_data(),
                NUM_LEAVES,
                bad_batch,
                PoolLimits::default(),
            )
            .expect_err("out-of-range batch_size must be rejected");
            assert!(err.to_string().contains("batch_size"), "got: {err}");
        }
    }

    #[test]
    fn proofs_bucket_by_key() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key_a = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let key_a2 = pool
            .push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        let key_b = pool
            .push(prove_fake(&data, &targets, &fake(2, 13)))
            .unwrap();

        assert_eq!(key_a, key_a2);
        assert_ne!(key_a, key_b);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.num_buckets(), 2);

        let stats = pool.bucket_stats();
        let a = stats.iter().find(|s| s.key == key_a).unwrap();
        assert_eq!(a.num_proofs, 2);
        assert!(a.is_full());
        assert_eq!(a.total_volume, 300);
        let b = stats.iter().find(|s| s.key == key_b).unwrap();
        assert_eq!(b.num_proofs, 1);
        assert!(!b.is_full());
    }

    /// First public-input felt of a proof's nullifier (test proofs use
    /// single-felt nullifiers), to assert snapshot ordering.
    fn nullifier_felt(proof: &Proof) -> u64 {
        proof.public_inputs[aggregated_output::nullifiers_start(NUM_LEAVES)].to_canonical_u64()
    }

    #[test]
    fn buckets_queue_deeper_than_one_batch() {
        let (mut pool, data, targets) = make_pool(1, PoolLimits::default());

        // batch_size is 1, but a hot key keeps admitting past it.
        for n in [11, 12, 13] {
            pool.push(prove_fake(&data, &targets, &fake(1, n))).unwrap();
        }
        assert_eq!(pool.len(), 3);

        let stats = pool.bucket_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].num_proofs, 3);
        assert!(stats[0].is_full());
    }

    /// The custody property the non-consuming design exists for: a proving
    /// snapshot never disturbs the pool. The pooled proof may be the only
    /// copy in the network (a claiming miner withholds it from relay), so a
    /// crashed or panicked proving worker must lose nothing — no recovery
    /// protocol, no resubmission needed.
    #[test]
    fn crashed_proving_worker_loses_nothing() {
        let (mut pool, data, targets) = make_pool(1, PoolLimits::default());
        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();

        let snapshot = pool.snapshot_batch(&key).expect("bucket must exist");
        let worker = std::thread::spawn(move || {
            let _owned = snapshot;
            panic!("simulated proving failure");
        });
        assert!(worker.join().is_err());

        // The pool never changed: the proof is still there, still snapshot-able.
        assert_eq!(pool.len(), 1);
        let retry = pool.snapshot_batch(&key).unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(nullifier_felt(&retry[0]), 11);
    }

    #[test]
    fn snapshot_batch_clones_oldest_up_to_batch_size() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 13)))
            .unwrap();

        // Oldest batch_size proofs, in admission order; nothing removed.
        let snapshot = pool.snapshot_batch(&key).unwrap();
        let nullifiers: Vec<u64> = snapshot.iter().map(nullifier_felt).collect();
        assert_eq!(nullifiers, vec![11, 12]);
        assert_eq!(pool.len(), 3);

        // Snapshots are repeatable and admissions keep landing behind them.
        pool.push(prove_fake(&data, &targets, &fake(1, 14)))
            .unwrap();
        let again = pool.snapshot_batch(&key).unwrap();
        let nullifiers: Vec<u64> = again.iter().map(nullifier_felt).collect();
        assert_eq!(nullifiers, vec![11, 12]);

        // Only settlement retires the proved inputs; the next snapshot is the
        // remainder, oldest first.
        let settled: HashSet<BytesDigest> = [nullifier_digest(11), nullifier_digest(12)]
            .into_iter()
            .collect();
        assert_eq!(pool.evict_settled(&settled), 2);
        let next = pool.snapshot_batch(&key).unwrap();
        let nullifiers: Vec<u64> = next.iter().map(nullifier_felt).collect();
        assert_eq!(nullifiers, vec![13, 14]);
    }

    #[test]
    fn duplicate_of_spend_being_proved_is_rejected() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let _snapshot = pool.snapshot_batch(&key).unwrap();

        // The client re-submits the same spend while its proof is being
        // proved — this time proven against a DIFFERENT block. The proof
        // never left the pool, so the duplicate is rejected like any other.
        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 11)))
            .unwrap_err();
        assert!(err.to_string().contains("already staged"), "got: {err}");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.num_buckets(), 1);
    }

    /// The duplicate-nullifier rejection must not disclose internal pool state
    /// to untrusted submitters: not the staged nullifier value and not the
    /// block the staged copy referenced.
    #[test]
    fn duplicate_rejection_does_not_leak_pool_state() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();

        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 11)))
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains(&format!("{:?}", nullifier_digest(11))),
            "leaks staged nullifier: {msg}"
        );
        // The staged copy referenced block 1 (its block hash is the same
        // 4-felt encoding nullifier_digest uses). The submitter only supplied
        // block 2, so block 1 must never appear in the error.
        assert!(
            !msg.contains(&format!("{:?}", nullifier_digest(1))),
            "leaks staged bucket block hash: {msg}"
        );
    }

    /// The duplicate check must run AFTER cryptographic verification and the
    /// verify budget, so it can't be probed as a free membership oracle with
    /// cryptographically invalid proofs. A well-formed but invalid proof that
    /// reuses a staged nullifier must be rejected as invalid, never revealed as
    /// a duplicate.
    #[test]
    fn duplicate_check_runs_after_verification() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();

        // Same nullifier (11), tampered so verification fails.
        let mut invalid = prove_fake(&data, &targets, &fake(2, 11));
        invalid.public_inputs[aggregated_output::ASSET_ID_OFFSET] = F::from_canonical_u64(9);
        let err = pool.push(invalid).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "duplicate check must not short-circuit ahead of verification, got: {err}"
        );
    }

    /// A competing miner settles a spend while its proof is being proved from
    /// a snapshot. Because proving is non-consuming, the proof is still
    /// resident and the per-block evict_settled cadence removes it
    /// IMMEDIATELY — there is no out-for-proving blind spot to remember and
    /// reconcile later.
    #[test]
    fn settlement_during_proving_evicts_immediately() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        let _snapshot = pool.snapshot_batch(&key).unwrap();

        let settled: HashSet<BytesDigest> = [nullifier_digest(11)].into_iter().collect();
        assert_eq!(pool.evict_settled(&settled), 1);

        // The next proving attempt sees only the live proof.
        let next = pool.snapshot_batch(&key).unwrap();
        let nullifiers: Vec<u64> = next.iter().map(nullifier_felt).collect();
        assert_eq!(nullifiers, vec![12]);
    }

    #[test]
    fn nullifier_index_stays_consistent_through_pool_mutations() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        // remove_bucket must unindex its nullifiers so they can be re-pooled.
        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.remove_bucket(&key);
        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();

        // A snapshot does not unindex: re-pushing the nullifier while the
        // batch is being proved is still rejected as a duplicate.
        let _snapshot = pool.snapshot_batch(&key).unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap_err();
        assert!(err.to_string().contains("already staged"), "got: {err}");

        // ...and eviction through the index still finds the proof.
        let settled: HashSet<BytesDigest> = [nullifier_digest(11)].into_iter().collect();
        assert_eq!(pool.evict_settled(&settled), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn duplicate_nullifier_in_bucket_is_rejected() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap_err();
        assert!(err.to_string().contains("already staged"), "got: {err}");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn duplicate_nullifier_is_rejected_across_buckets() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        // The cumulative merkle tree lets the SAME spend be proven against two
        // different recent blocks: individually valid proofs, same nullifier,
        // different BatchKeys. Only one copy can settle, so the second must be
        // rejected pool-wide, not just within its own bucket.
        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 11)))
            .unwrap_err();
        assert!(err.to_string().contains("already staged"), "got: {err}");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.num_buckets(), 1);

        // Once the original is evicted (settled), the nullifier frees up.
        let settled: HashSet<BytesDigest> = [nullifier_digest(11)].into_iter().collect();
        assert_eq!(pool.evict_settled(&settled), 1);
        pool.push(prove_fake(&data, &targets, &fake(2, 11)))
            .unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let mut proof = prove_fake(&data, &targets, &fake(1, 11));
        proof.public_inputs[aggregated_output::ASSET_ID_OFFSET] = F::from_canonical_u64(9);
        let err = pool.push(proof).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "got: {err}"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn wrong_pi_length_is_rejected() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let mut proof = prove_fake(&data, &targets, &fake(1, 11));
        proof.public_inputs.pop();
        let err = pool.push(proof).unwrap_err();
        assert!(
            err.to_string().contains("public input length mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn global_proof_cap_is_enforced() {
        let (mut pool, data, targets) = make_pool(
            1,
            PoolLimits {
                max_proofs: 1,
                max_buckets: 8,
                ..PoolLimits::default()
            },
        );

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 12)))
            .unwrap_err();
        assert!(err.to_string().contains("pool is full"), "got: {err}");
    }

    /// Proofs being proved from a snapshot stay resident, so `max_proofs`
    /// bounds them with no separate out-for-proving accounting — the cap
    /// overshoot the old take/reinsert lifecycle allowed (audit finding)
    /// cannot be expressed anymore.
    #[test]
    fn proofs_being_proved_still_occupy_capacity() {
        let (mut pool, data, targets) = make_pool(
            2,
            PoolLimits {
                max_proofs: 2,
                ..PoolLimits::default()
            },
        );

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        let _snapshot = pool.snapshot_batch(&key).unwrap();

        // The snapshot freed nothing: the pool is still full.
        let err = pool
            .push(prove_fake(&data, &targets, &fake(1, 13)))
            .unwrap_err();
        assert!(err.to_string().contains("pool is full"), "got: {err}");
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn bucket_cap_is_enforced() {
        let (mut pool, data, targets) = make_pool(
            1,
            PoolLimits {
                max_proofs: 16,
                max_buckets: 1,
                ..PoolLimits::default()
            },
        );

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 12)))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bucket limit"), "got: {msg}");
        // Must not echo the rejected (or any pooled) block hash: the
        // submitter already knows their own key, and naming it (or a
        // staged one) would make the distinct "bucket limit" error a
        // confirmation channel for which keys are pooled.
        assert!(
            !msg.contains(&format!("{:?}", nullifier_digest(1)))
                && !msg.contains(&format!("{:?}", nullifier_digest(2))),
            "bucket-cap rejection must not echo block hashes: {msg}"
        );
    }

    /// The bucket-cap membership test (`buckets.contains_key`) must run AFTER
    /// cryptographic verification and the verify budget. Otherwise, once the
    /// pool is at `max_buckets`, a well-formed-but-invalid probe carrying a
    /// candidate key is rejected instantly with "bucket limit" when the key
    /// is novel, but falls through to ~10-20ms verification when the key is
    /// already pooled — a free membership oracle over which
    /// (block, asset, fee) tuples the miner is aggregating (audit finding).
    #[test]
    fn bucket_cap_check_runs_after_verification() {
        let (mut pool, data, targets) = make_pool(
            1,
            PoolLimits {
                max_proofs: 16,
                max_buckets: 1,
                ..PoolLimits::default()
            },
        );

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();

        // Novel key (block 2), tampered so verification fails. Pre-fix this
        // short-circuited on the bucket cap and returned "bucket limit"
        // without verifying — confirming the key was not pooled. Post-fix
        // it must fail verification first.
        let mut novel_invalid = prove_fake(&data, &targets, &fake(2, 12));
        novel_invalid.public_inputs[aggregated_output::ASSET_ID_OFFSET] =
            F::from_canonical_u64(9);
        let err = pool.push(novel_invalid).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "bucket-cap check must not short-circuit ahead of verification for a \
             novel key, got: {err}"
        );

        // Existing key (block 1), also tampered. Same path: verify first,
        // never a bucket-cap answer that would confirm membership.
        let mut existing_invalid = prove_fake(&data, &targets, &fake(1, 13));
        existing_invalid.public_inputs[aggregated_output::ASSET_ID_OFFSET] =
            F::from_canonical_u64(9);
        let err = pool.push(existing_invalid).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "got: {err}"
        );
        assert!(
            !err.to_string().contains("bucket limit"),
            "invalid proofs must not observe the bucket-cap branch: {err}"
        );
    }

    /// Verification CPU must be bounded even though invalid proofs never
    /// consume a pool slot: once the per-window budget is exhausted, push
    /// rejects cheaply before the expensive recursive verification.
    #[test]
    fn verification_budget_bounds_admission_attempts() {
        let (mut pool, data, targets) = make_pool(
            4,
            PoolLimits {
                max_verifies_per_window: 2,
                verify_window: Duration::from_secs(3600),
                ..PoolLimits::default()
            },
        );

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();

        // Budget exhausted: even a valid proof is rejected without verifying.
        let err = pool
            .push(prove_fake(&data, &targets, &fake(1, 13)))
            .unwrap_err();
        assert!(
            err.to_string().contains("verification budget exhausted"),
            "got: {err}"
        );
    }

    /// Failed verification attempts charge the budget too — that's the whole
    /// point (attempts cost CPU, not admissions) — and the budget resets once
    /// the window rolls over.
    #[test]
    fn verification_budget_counts_failures_and_resets() {
        let (mut pool, data, targets) = make_pool(
            4,
            PoolLimits {
                max_verifies_per_window: 1,
                verify_window: Duration::from_secs(2),
                ..PoolLimits::default()
            },
        );

        // Build both proofs BEFORE the first push: proving takes long enough
        // that doing it between pushes could roll the window over and flake.
        let mut bad = prove_fake(&data, &targets, &fake(1, 11));
        bad.public_inputs[aggregated_output::ASSET_ID_OFFSET] = F::from_canonical_u64(9);
        let good = prove_fake(&data, &targets, &fake(1, 12));

        // The tampered proof burns the single budgeted attempt.
        let err = pool.push(bad).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "got: {err}"
        );

        let err = pool.push(good.clone()).unwrap_err();
        assert!(
            err.to_string().contains("verification budget exhausted"),
            "got: {err}"
        );

        // After the window rolls over, admission resumes.
        std::thread::sleep(Duration::from_millis(2100));
        pool.push(good).unwrap();
    }

    /// Settlement can only reclaim proofs whose nullifiers reach the chain; a
    /// proof that lost its inclusion race would occupy `max_proofs` forever.
    /// `evict_older_than` is the expiry backstop: it removes exactly the
    /// proofs older than the cutoff (per proof, not per bucket), drops
    /// emptied buckets, and unindexes the evicted nullifiers.
    #[test]
    fn evict_older_than_reclaims_expired_proofs() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        // Build all proofs up front: proving is slow enough that doing it
        // between pushes would blur the admission-age gap asserted below.
        let old_a = prove_fake(&data, &targets, &fake(1, 11));
        let old_b = prove_fake(&data, &targets, &fake(2, 12));
        let young = prove_fake(&data, &targets, &fake(1, 13));

        let key_a = pool.push(old_a).unwrap();
        let key_b = pool.push(old_b).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        pool.push(young).unwrap();

        // Cutoff between the two admission times: only the old proofs expire.
        assert_eq!(pool.evict_older_than(Duration::from_millis(100)), 2);
        assert_eq!(pool.len(), 1);

        // key_b's only proof expired, so its bucket is gone; key_a keeps the
        // young proof.
        assert_eq!(pool.num_buckets(), 1);
        assert!(pool.snapshot_batch(&key_b).is_none());
        let remaining = pool.snapshot_batch(&key_a).unwrap();
        assert_eq!(nullifier_felt(&remaining[0]), 13);

        // The evicted nullifiers were unindexed: the same spend can re-pool.
        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        assert_eq!(pool.len(), 2);

        // A generous cutoff evicts nothing.
        assert_eq!(pool.evict_older_than(Duration::from_secs(3600)), 0);
        assert_eq!(pool.len(), 2);
    }

    /// `last_snapshot_age` is the policy layer's in-flight signal: `None`
    /// until a bucket is first snapshot, then the time since the latest
    /// snapshot — so a policy loop can skip buckets whose submitted batch is
    /// plausibly still settling instead of re-proving them every cycle.
    #[test]
    fn bucket_stats_track_last_snapshot_age() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        assert_eq!(pool.bucket_stats()[0].last_snapshot_age, None);

        let _snapshot = pool.snapshot_batch(&key).unwrap();
        let age = pool.bucket_stats()[0]
            .last_snapshot_age
            .expect("snapshot must be recorded");
        assert!(age < Duration::from_secs(5), "age must be fresh: {age:?}");

        // Admissions don't disturb the mark.
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        assert!(pool.bucket_stats()[0].last_snapshot_age.is_some());
    }

    #[test]
    fn evict_settled_removes_proofs_and_empty_buckets() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key_a = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        let key_b = pool
            .push(prove_fake(&data, &targets, &fake(2, 13)))
            .unwrap();

        let settled: HashSet<BytesDigest> = [nullifier_digest(11), nullifier_digest(13)]
            .into_iter()
            .collect();
        let evicted = pool.evict_settled(&settled);

        assert_eq!(evicted, 2);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.num_buckets(), 1);
        assert!(pool.snapshot_batch(&key_a).is_some());
        assert!(pool.snapshot_batch(&key_b).is_none());
    }

    #[test]
    fn remove_bucket_returns_proofs() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();

        let drained = pool.remove_bucket(&key);
        assert_eq!(drained.len(), 2);
        assert!(pool.is_empty());
        assert!(pool.remove_bucket(&key).is_empty());
    }

    #[test]
    fn all_dummy_proof_is_rejected_at_admission() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        // A valid all-dummy proof (block_hash == 0) must not be pooled: no
        // automatic drain path could ever remove it, so it would count against
        // the global capacity forever (attacker sink).
        let err = pool
            .push(prove_fake(&data, &targets, &fake(0, 11)))
            .unwrap_err();
        assert!(err.to_string().contains("all-dummy"), "got: {err}");
        assert!(pool.is_empty());

        // ...and its nullifier is NOT indexed: the same spend proven against a
        // real block afterwards is still admissible.
        let key = pool
            .push(prove_fake(&data, &targets, &fake(3, 11)))
            .unwrap();
        assert!(!key.is_dummy());
        assert_eq!(pool.len(), 1);
    }
}
