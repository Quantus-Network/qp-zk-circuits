//! Proof pool for delegated (public-batch) aggregation.
//!
//! A miner-facing, in-memory pool of private-batch proofs received from
//! untrusted clients. Proofs are cryptographically verified on admission and
//! bucketed by the metadata the public-batch circuit constrains across a batch
//! (block hash, asset id, volume fee), so every bucket is aggregatable by
//! construction: the "when to aggregate which bucket" decision is left to the
//! operator's policy, fed by [`BucketStats`].
//!
//! Buckets queue arbitrarily deep (bounded only by [`PoolLimits`]), so a hot
//! (block, asset, fee) stream keeps admitting while earlier batches are being
//! proved. [`ProofPool::take_batch`] removes the oldest `batch_size` proofs as
//! an opaque [`TakenBatch`]; prove it without holding any pool lock, then drop
//! it on success or [`ProofPool::reinsert`] it on failure (no re-verification).
//!
//! Staleness: a queued proof becomes worthless once any of its nullifiers is
//! settled on-chain (e.g. another miner included the same private batch, or a
//! public batch containing it). Operators should call
//! [`ProofPool::evict_settled`] with newly settled nullifiers on every imported
//! block — both before proving (don't aggregate dead weight) and before
//! submitting a finished public batch (don't submit stale segments).
//!
//! Note on dummies: an all-dummy private-batch proof (all-zero block hash) is
//! admissible — it is a valid proof and lands in its own bucket — but it
//! settles nothing, so it must never be selected for aggregation
//! ([`BucketStats::is_dummy`] flags it, and the `PublicBatchAggregator` façade
//! refuses to take it; the pool itself stays policy-free).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Result};
use plonky2::field::types::PrimeField64;
use plonky2::plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs};
use qp_wormhole_inputs::BytesDigest;
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
    /// Maximum number of proofs across all buckets.
    pub max_proofs: usize,
    /// Maximum number of distinct buckets (keys).
    pub max_buckets: usize,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_proofs: 1024,
            max_buckets: 256,
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
    /// Public-batch size: how many proofs one `take_batch` removes, and the
    /// count at which a batch aggregates without dummy padding.
    pub batch_size: usize,
    /// Time since the oldest queued proof in this bucket was admitted.
    pub oldest_age: Duration,
    /// Sum of all exit-slot amounts across queued proofs (settled volume proxy).
    pub total_volume: u64,
}

impl BucketStats {
    /// Whether the bucket holds at least one full (padding-free) batch.
    pub fn is_full(&self) -> bool {
        self.num_proofs >= self.batch_size
    }

    /// Whether this is the dummy sentinel bucket (`block_hash == 0`).
    /// Aggregating it proves a public batch that settles nothing; policy code
    /// must skip it (`PublicBatchAggregator` refuses it outright).
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

/// A batch of admission-verified proofs removed from the pool for proving.
///
/// Opaque by design: it can only be produced by [`ProofPool::take_batch`], so
/// [`ProofPool::reinsert`] can restore it on proving failure without repeating
/// cryptographic verification. Callers must either prove-and-drop it (success)
/// or reinsert it (failure); dropping it silently discards the proofs.
#[derive(Debug)]
pub struct TakenBatch {
    key: BatchKey,
    proofs: Vec<PooledProof>,
}

impl TakenBatch {
    pub fn key(&self) -> &BatchKey {
        &self.key
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Clone the contained proofs (e.g. to feed a prover's `commit`).
    pub fn proofs(&self) -> Vec<Proof> {
        self.proofs.iter().map(|q| q.proof.clone()).collect()
    }
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
    buckets: BTreeMap<BatchKey, Vec<PooledProof>>,
    /// Global index of every pooled nullifier to the bucket holding its proof.
    ///
    /// Duplicates are rejected pool-wide, not just per bucket: the merkle tree
    /// is cumulative, so the SAME spend can be validly proven against two
    /// different recent blocks, landing in different buckets — only one copy
    /// can ever settle. The index also makes [`Self::evict_settled`] a lookup
    /// instead of a full pool scan. Invariant: contains exactly the nullifiers
    /// of proofs currently in `buckets` (taken batches are not indexed).
    nullifier_index: HashMap<BytesDigest, BatchKey>,
}

impl ProofPool {
    /// Create a pool admitting proofs valid under `verifier`.
    ///
    /// `inner_num_leaves` is the number of leaves aggregated per private-batch
    /// proof and `batch_size` the number of private-batch proofs per public
    /// batch; both must match the circuit shapes pinned into `verifier` and the
    /// public-batch prover this pool feeds.
    pub fn new(
        verifier: VerifierCircuitData<F, C, D>,
        inner_num_leaves: usize,
        batch_size: usize,
        limits: PoolLimits,
    ) -> Result<Self> {
        ensure!(batch_size > 0, "batch_size must be positive");
        ensure!(
            limits.max_proofs >= batch_size,
            "max_proofs ({}) must allow at least one full batch ({})",
            limits.max_proofs,
            batch_size
        );
        ensure!(limits.max_buckets > 0, "max_buckets must be positive");
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
        })
    }

    /// Total number of proofs across all buckets.
    pub fn len(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
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
    /// Checks run cheapest-first: capacity limits, public-input shape,
    /// duplicate-nullifier rejection, then cryptographic verification. A proof
    /// admitted here is individually valid and, by bucketing, batch-compatible
    /// with every other proof in its bucket, so aggregation over a bucket
    /// cannot fail deterministically on admitted inputs (#97067).
    ///
    /// Buckets are NOT capped at one batch: a hot key keeps admitting (up to
    /// the global limits) while earlier batches for it are out being proved;
    /// [`Self::take_batch`] takes the oldest `batch_size` proofs at a time.
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

        // A duplicate nullifier anywhere in the pool means the same leaf spend
        // is already staged; only one copy can ever settle. This is checked
        // pool-wide (not per bucket): the cumulative merkle tree lets the same
        // spend be proven against different recent blocks, i.e. into different
        // buckets. It also deduplicates client re-submissions.
        if let Some(dup) = metadata
            .1
            .iter()
            .find(|n| self.nullifier_index.contains_key(n))
        {
            bail!(
                "refusing to queue private-batch proof: nullifier {:?} is already \
                 pooled (in bucket for block {:?})",
                dup,
                self.nullifier_index[dup].block_hash
            );
        }

        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.limits.max_buckets {
            bail!(
                "proof pool bucket limit reached ({} buckets); \
                 proof for block {:?} rejected",
                self.limits.max_buckets,
                key.block_hash
            );
        }

        self.verifier.verify(proof.clone()).map_err(|e| {
            anyhow!(
                "refusing to queue invalid private-batch proof: verification failed: {}",
                e
            )
        })?;

        let (key, nullifiers, volume) = metadata;
        for nullifier in &nullifiers {
            self.nullifier_index.insert(*nullifier, key);
        }
        self.buckets.entry(key).or_default().push(PooledProof {
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
            bucket.retain(|queued| {
                let stale = queued.nullifiers.iter().any(|n| settled.contains(n));
                if stale {
                    evicted += 1;
                    for n in &queued.nullifiers {
                        self.nullifier_index.remove(n);
                    }
                }
                !stale
            });
            if bucket.is_empty() {
                self.buckets.remove(&key);
            }
        }
        evicted
    }

    /// Per-bucket statistics for the operator's aggregation policy.
    pub fn bucket_stats(&self) -> Vec<BucketStats> {
        let now = Instant::now();
        self.buckets
            .iter()
            .map(|(key, bucket)| BucketStats {
                key: *key,
                num_proofs: bucket.len(),
                batch_size: self.batch_size,
                oldest_age: bucket
                    .iter()
                    .map(|q| now.saturating_duration_since(q.admitted_at))
                    .max()
                    .unwrap_or_default(),
                total_volume: bucket
                    .iter()
                    .fold(0u64, |acc, q| acc.saturating_add(q.volume)),
            })
            .collect()
    }

    /// Clone the proofs of one bucket (for aggregation attempts that must not
    /// disturb the pool on failure).
    pub fn bucket_proofs(&self, key: &BatchKey) -> Option<Vec<Proof>> {
        self.buckets
            .get(key)
            .map(|bucket| bucket.iter().map(|q| q.proof.clone()).collect())
    }

    /// Remove up to `batch_size` of the oldest proofs for `key`, for proving.
    ///
    /// This is the non-blocking aggregation primitive: taking is cheap, so a
    /// service can take under a short lock, prove for minutes WITHOUT holding
    /// any pool lock (admissions for the same key keep landing in the bucket
    /// remainder), then drop the batch on success or [`Self::reinsert`] it on
    /// failure. Returns `None` if the bucket doesn't exist.
    pub fn take_batch(&mut self, key: &BatchKey) -> Option<TakenBatch> {
        let bucket = self.buckets.get_mut(key)?;
        let n = bucket.len().min(self.batch_size);
        let taken: Vec<PooledProof> = bucket.drain(..n).collect();
        if bucket.is_empty() {
            self.buckets.remove(key);
        }
        // Taken proofs leave the pool, so their nullifiers leave the index;
        // `reinsert` re-checks for duplicates admitted while the batch was out.
        for queued in &taken {
            for nullifier in &queued.nullifiers {
                self.nullifier_index.remove(nullifier);
            }
        }
        Some(TakenBatch { key: *key, proofs: taken })
    }

    /// Restore a taken batch after a failed proving attempt, WITHOUT repeating
    /// cryptographic verification (the batch is only constructable from this
    /// pool's own admission path).
    ///
    /// Proofs are restored at the front of their bucket, preserving age order.
    /// A proof whose nullifier was re-admitted (to any bucket) while the batch
    /// was out is dropped as a duplicate (the copies are interchangeable
    /// spends). Returns the number of proofs actually restored.
    ///
    /// NOTE: proofs may have gone stale while out (settled by another miner);
    /// they are subject to the next [`Self::evict_settled`] like any other.
    pub fn reinsert(&mut self, batch: TakenBatch) -> usize {
        let restored: Vec<PooledProof> = batch
            .proofs
            .into_iter()
            .filter(|q| {
                !q.nullifiers
                    .iter()
                    .any(|n| self.nullifier_index.contains_key(n))
            })
            .collect();
        let count = restored.len();
        for queued in &restored {
            for nullifier in &queued.nullifiers {
                self.nullifier_index.insert(*nullifier, batch.key);
            }
        }

        let bucket = self.buckets.entry(batch.key).or_default();
        let mut merged = restored;
        merged.append(bucket);
        *bucket = merged;
        if bucket.is_empty() {
            self.buckets.remove(&batch.key);
        }
        count
    }

    /// Remove one bucket entirely, returning its proofs (empty if absent).
    ///
    /// Used both to drain a bucket after successful aggregation and as an
    /// operator recovery/expiry path for buckets that will never be aggregated.
    pub fn remove_bucket(&mut self, key: &BatchKey) -> Vec<Proof> {
        self.buckets
            .remove(key)
            .map(|bucket| {
                bucket
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
    /// single-felt nullifiers), to assert take/reinsert ordering.
    fn nullifier_felt(proof: &Proof) -> u64 {
        proof.public_inputs[aggregated_output::nullifiers_start(NUM_LEAVES)].to_canonical_u64()
    }

    #[test]
    fn buckets_queue_deeper_than_one_batch() {
        let (mut pool, data, targets) = make_pool(1, PoolLimits::default());

        // batch_size is 1, but a hot key keeps admitting past it.
        for n in [11, 12, 13] {
            pool.push(prove_fake(&data, &targets, &fake(1, n)))
                .unwrap();
        }
        assert_eq!(pool.len(), 3);

        let stats = pool.bucket_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].num_proofs, 3);
        assert!(stats[0].is_full());
    }

    #[test]
    fn take_batch_takes_oldest_and_leaves_remainder() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 13)))
            .unwrap();

        let taken = pool.take_batch(&key).unwrap();
        assert_eq!(taken.key(), &key);
        let taken_nullifiers: Vec<u64> = taken.proofs().iter().map(nullifier_felt).collect();
        assert_eq!(taken_nullifiers, vec![11, 12]);
        assert_eq!(pool.len(), 1);

        // The remainder is the next batch (partial), and admissions continue.
        pool.push(prove_fake(&data, &targets, &fake(1, 14)))
            .unwrap();
        let next = pool.take_batch(&key).unwrap();
        let next_nullifiers: Vec<u64> = next.proofs().iter().map(nullifier_felt).collect();
        assert_eq!(next_nullifiers, vec![13, 14]);
        assert!(pool.is_empty());
        assert!(pool.take_batch(&key).is_none());
    }

    #[test]
    fn reinsert_restores_age_order_without_reverification() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        pool.push(prove_fake(&data, &targets, &fake(1, 12)))
            .unwrap();

        let taken = pool.take_batch(&key).unwrap();
        // A newer proof lands while the batch is out being proved.
        pool.push(prove_fake(&data, &targets, &fake(1, 13)))
            .unwrap();

        assert_eq!(pool.reinsert(taken), 2);
        assert_eq!(pool.len(), 3);

        // The reinserted (older) proofs come out first on the next take.
        let retaken = pool.take_batch(&key).unwrap();
        let nullifiers: Vec<u64> = retaken.proofs().iter().map(nullifier_felt).collect();
        assert_eq!(nullifiers, vec![11, 12]);
    }

    #[test]
    fn reinsert_drops_nullifiers_readmitted_while_out() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let taken = pool.take_batch(&key).unwrap();

        // The client re-submits the same spend while its proof is out — this
        // time proven against a DIFFERENT block, so it lands in another
        // bucket. Admission succeeds because taken proofs are out of the pool.
        pool.push(prove_fake(&data, &targets, &fake(2, 11)))
            .unwrap();

        // Reinserting must not duplicate the nullifier anywhere in the pool.
        assert_eq!(pool.reinsert(taken), 0);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.num_buckets(), 1);
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

        // take + reinsert round-trips the index: re-pushing the nullifier
        // afterwards is still rejected as a duplicate.
        let taken = pool.take_batch(&key).unwrap();
        assert_eq!(pool.reinsert(taken), 1);
        let err = pool
            .push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap_err();
        assert!(err.to_string().contains("already pooled"), "got: {err}");

        // ...and eviction through the index still finds the reinserted proof.
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
        assert!(err.to_string().contains("already pooled"), "got: {err}");
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
        assert!(err.to_string().contains("already pooled"), "got: {err}");
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
            },
        );

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 12)))
            .unwrap_err();
        assert!(err.to_string().contains("pool is full"), "got: {err}");
    }

    #[test]
    fn bucket_cap_is_enforced() {
        let (mut pool, data, targets) = make_pool(
            1,
            PoolLimits {
                max_proofs: 16,
                max_buckets: 1,
            },
        );

        pool.push(prove_fake(&data, &targets, &fake(1, 11)))
            .unwrap();
        let err = pool
            .push(prove_fake(&data, &targets, &fake(2, 12)))
            .unwrap_err();
        assert!(err.to_string().contains("bucket limit"), "got: {err}");
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
        assert!(pool.bucket_proofs(&key_a).is_some());
        assert!(pool.bucket_proofs(&key_b).is_none());
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
    fn dummy_key_is_detected() {
        let (mut pool, data, targets) = make_pool(2, PoolLimits::default());

        let key = pool
            .push(prove_fake(&data, &targets, &fake(0, 11)))
            .unwrap();
        assert!(key.is_dummy());
        let key = pool
            .push(prove_fake(&data, &targets, &fake(3, 12)))
            .unwrap();
        assert!(!key.is_dummy());
    }
}
