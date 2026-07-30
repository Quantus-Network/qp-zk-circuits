//! Delegated (public-batch) aggregation service.
//!
//! [`PublicBatchAggregator`] is the miner-facing component: it pools
//! private-batch proofs received from untrusted clients (admission-verified and
//! bucketed by batch compatibility, see [`crate::pool`]) and aggregates one
//! bucket at a time into a public-batch proof bound to this aggregator's
//! address.
//!
//! Client-side (private-batch) aggregation intentionally has no queue: a client
//! knows its own full leaf set up front, so it uses
//! [`PrivateBatchProver::aggregate`](crate::private_batch::prover::PrivateBatchProver::aggregate)
//! directly.
//!
//! # Concurrency
//!
//! Public-batch proving takes tens of seconds (~16 s for a 53-proof batch on
//! Apple-Silicon-class hardware; a few block times, so settlements can land
//! mid-prove). [`PublicBatchAggregator::aggregate`] is the simple blocking
//! convenience; a service that must keep admitting proofs while proving
//! should snapshot under a short lock and prove without it:
//!
//! ```text
//! // policy loop, short exclusive lock (snapshot_batch takes &mut self —
//! // it records the snapshot time, so racing policy workers see each
//! // other's mark instead of both proving the same key):
//! let proofs = aggregator.lock().snapshot_batch(&key)?;
//!
//! // proving worker, NO lock held — prove from the aggregator's pinned
//! // artifacts (never re-read the mutable bins_dir):
//! let proof = aggregator.lock().prove_batch(proofs)?;
//! // submit `proof`; the block-import evict_settled cadence retires the
//! // proved inputs from the pool once their segments settle on-chain.
//! ```
//!
//! Proving is NON-CONSUMING: the snapshot is a clone and the pooled originals
//! stay put, because a claiming miner's pool may hold the only copy of a
//! proof in the network (see the custody section in [`crate::pool`]). A
//! failed or crashed proving worker therefore needs no recovery protocol —
//! the pool never changed — and buckets queue deeper than one batch, so
//! admissions for the same key keep landing while it is being proved.
//!
//! Because success does not drain the bucket, a policy loop must NOT blindly
//! re-aggregate the same key every cycle: until settlement lands (a few
//! block times), each re-prove burns a full proving run to produce a
//! duplicate submission. Use [`BucketStats::last_snapshot_age`] to skip
//! buckets with a submission plausibly still in flight.
//!
//! The removal paths are settlement eviction
//! ([`PublicBatchAggregator::evict_settled`], call it on every imported
//! block), expiry ([`PublicBatchAggregator::evict_older_than`] — operators
//! MUST run it, or their own expiry policy, on a cadence; see the expiry
//! section in [`crate::pool`]), and the operator override
//! [`PublicBatchAggregator::remove_bucket`].

use anyhow::{anyhow, bail, Context, Result};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierCircuitData},
    proof::ProofWithPublicInputs,
};
use qp_wormhole_inputs::{public_batch_pi::AGGREGATOR_ADDRESS_LEN, BytesDigest};
use std::collections::HashSet;
use std::path::Path;

use zk_circuits_common::{
    circuit::{wormhole_public_batch_circuit_config, C, D, F},
    utils::try_4_felts_to_bytes,
};

use crate::pool::{BatchKey, BucketStats, PoolLimits, ProofPool};
use crate::public_batch::prover::{
    verify_dummy_private_batch_template, PublicBatchInputs, PublicBatchProver,
};
use crate::{
    common::utils::{
        canonical_leaf_verifier_data, canonical_public_batch_verifier_data,
        ensure_proof_public_input_len, ensure_verifier_data_matches_canonical,
        load_canonical_private_batch_verifier_data, load_verifier_data_from_bytes,
    },
    CircuitBinsConfig,
};

type Proof = ProofWithPublicInputs<F, C, D>;

// ============================================================================
// Verifier-loading helpers
// ============================================================================

fn read_bin(bins_dir: &Path, file: &str) -> Result<Vec<u8>> {
    crate::common::utils::read_artifact_file(&bins_dir.join(file))
        .with_context(|| format!("failed to read {}", bins_dir.join(file).display()))
}

fn load_private_batch_verifier_from_bins(
    bins_dir: &Path,
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    let leaf = canonical_leaf_verifier_data();
    load_canonical_private_batch_verifier_data(
        &read_bin(bins_dir, "private_batch_common.bin")?,
        &read_bin(bins_dir, "private_batch_verifier.bin")?,
        &leaf,
        num_leaf_proofs,
    )
}

fn load_public_batch_verifier_from_bins(
    bins_dir: &Path,
    private_batch: &VerifierCircuitData<F, C, D>,
    num_leaf_proofs: usize,
    num_private_batch_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    let loaded = load_verifier_data_from_bytes(
        &read_bin(bins_dir, "public_batch_common.bin")?,
        &read_bin(bins_dir, "public_batch_verifier.bin")?,
        "public_batch",
    )?;
    let canonical = canonical_public_batch_verifier_data(
        private_batch,
        num_private_batch_proofs,
        num_leaf_proofs,
    )?;
    ensure_verifier_data_matches_canonical(&loaded, &canonical, "public_batch")?;
    Ok(loaded)
}

// ============================================================================
// Public-batch aggregation service
// ============================================================================

pub struct PublicBatchAggregator {
    aggregator_address: BytesDigest,
    pool: ProofPool,
    /// Canonical-pinned public-batch verifier data, loaded once at construction.
    verifier: VerifierCircuitData<F, C, D>,
    /// Canonical-pinned private-batch verifier, used to build the public-batch
    /// prover on every [`Self::prove_batch`] without re-reading the artifact
    /// directory (which is mutable after construction).
    private_batch_verifier: VerifierCircuitData<F, C, D>,
    /// Pinned dummy private-batch padding template, validated at construction.
    dummy_proof_template: Proof,
    num_leaf_proofs: usize,
    num_private_batch_proofs: usize,
}

impl PublicBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P, aggregator_address: BytesDigest) -> Result<Self> {
        Self::with_limits(bins_dir, aggregator_address, PoolLimits::default())
    }

    /// Load and pin every artifact needed for pooling and proving.
    ///
    /// After construction the aggregator never reads `bins_dir` again: a
    /// filesystem attacker (or a later artifact publish) cannot change the
    /// circuit shape or dummy template under a proving call. Callers that
    /// need to rotate artifacts must construct a new aggregator.
    pub fn with_limits<P: AsRef<Path>>(
        bins_dir: P,
        aggregator_address: BytesDigest,
        limits: PoolLimits,
    ) -> Result<Self> {
        let bins_dir = bins_dir.as_ref();

        let config = CircuitBinsConfig::load(bins_dir)?;
        let num_private_batch_proofs = config
            .num_private_batch_proofs
            .ok_or_else(|| anyhow!("config is missing num_private_batch_proofs. Please regenerate the binaries and set \"num_private_batch_proofs\""))?;
        let num_leaf_proofs = config.num_leaf_proofs;

        let private_batch_verifier =
            load_private_batch_verifier_from_bins(bins_dir, num_leaf_proofs)?;
        let verifier = load_public_batch_verifier_from_bins(
            bins_dir,
            &private_batch_verifier,
            num_leaf_proofs,
            num_private_batch_proofs,
        )?;

        let dummy_proof_template = Proof::from_bytes(
            read_bin(bins_dir, "dummy_private_batch_proof.bin")?,
            &private_batch_verifier.common,
        )
        .map_err(|e| anyhow!("failed to deserialize dummy private-batch proof: {}", e))?;
        verify_dummy_private_batch_template(&dummy_proof_template, &private_batch_verifier)
            .context("dummy private-batch proof template failed validation at aggregator init")?;

        let pool = ProofPool::new(
            private_batch_verifier.clone(),
            num_leaf_proofs,
            num_private_batch_proofs,
            limits,
        )?;

        Ok(Self {
            aggregator_address,
            pool,
            verifier,
            private_batch_verifier,
            dummy_proof_template,
            num_leaf_proofs,
            num_private_batch_proofs,
        })
    }

    /// Validate a private-batch proof and admit it into the pool, returning the
    /// bucket key it landed in. See [`ProofPool::push`].
    pub fn push_proof(&mut self, proof: Proof) -> Result<BatchKey> {
        self.pool.push(proof)
    }

    /// Aggregate the oldest batch of one bucket into a public-batch proof
    /// bound to this aggregator's address. Partial batches are padded with the
    /// dummy private-batch template.
    ///
    /// NON-CONSUMING: the proved proofs stay pooled — they may exist nowhere
    /// else in the network (see the custody section in [`crate::pool`]) — so
    /// a failed attempt needs no cleanup, and calling this again before the
    /// submitted batch settles re-proves the same batch (check
    /// [`BucketStats::last_snapshot_age`] first; see the module docs).
    /// Removal happens through the block-import [`Self::evict_settled`]
    /// cadence once the batch's segments settle on-chain, through expiry
    /// ([`Self::evict_older_than`]), or via [`Self::remove_bucket`]. Proofs
    /// beyond `batch_size` stay queued for the next call.
    ///
    /// This convenience method blocks for the whole proving run (tens of
    /// seconds) and, taking `&mut self`, holds exclusive access to the
    /// aggregator throughout — which also means concurrent aggregation of
    /// the same key is serialized structurally. A concurrent service should
    /// use the split API instead: [`Self::snapshot_batch`] under a short
    /// lock, then [`Self::prove_batch`] on a proving worker WITHOUT holding
    /// the lock.
    pub fn aggregate(&mut self, key: &BatchKey) -> Result<Proof> {
        let proofs = self.snapshot_batch(key)?;
        self.prove_batch(proofs)
    }

    /// Clone the oldest up-to-`batch_size` proofs of one bucket, for proving
    /// via [`Self::prove_batch`]. Cheap and non-consuming; records the
    /// snapshot time (see [`BucketStats::last_snapshot_age`]) so policy can
    /// avoid re-proving an in-flight batch. See [`ProofPool::snapshot_batch`].
    ///
    /// Refuses the dummy sentinel bucket: an all-dummy public batch is a
    /// valid proof that settles nothing, so proving it only wastes the
    /// proving run. (Defense in depth — [`ProofPool::push`] already rejects
    /// all-dummy proofs, so the bucket should never exist.)
    pub fn snapshot_batch(&mut self, key: &BatchKey) -> Result<Vec<Proof>> {
        if key.is_dummy() {
            bail!(
                "refusing to aggregate the dummy sentinel bucket (block_hash == 0): \
                 an all-dummy public batch settles nothing"
            );
        }
        self.pool.snapshot_batch(key).ok_or_else(|| {
            anyhow!(
                "no pooled proofs for block {:?} (asset {}, fee {})",
                key.block_hash,
                key.asset_id,
                key.volume_fee_bps
            )
        })
    }

    /// Prove a snapshot of private-batch proofs into a public-batch proof
    /// bound to this aggregator's address. Does not touch the pool.
    ///
    /// Builds the public-batch prover from artifacts pinned at construction
    /// (private-batch verifier, dummy template, batch sizes) — never from the
    /// mutable `bins_dir` path. The returned proof is checked against the
    /// pinned [`Self::verify`] before being handed back, so a divergent prover
    /// build cannot silently return an unusable proof.
    ///
    /// Takes tens of seconds (~16 s for a 53-proof batch on
    /// Apple-Silicon-class hardware, plus prover load). In a concurrent
    /// service, run this on a dedicated proving worker without holding
    /// whatever lock guards the aggregator — the snapshot is already
    /// independent of the pool.
    pub fn prove_batch(&self, proofs: Vec<Proof>) -> Result<Proof> {
        let prover = PublicBatchProver::new(
            wormhole_public_batch_circuit_config(),
            self.private_batch_verifier.common.clone(),
            &self.private_batch_verifier.verifier_only,
            self.num_private_batch_proofs,
            self.num_leaf_proofs,
            self.dummy_proof_template.clone(),
        )
        .context("failed to build public-batch prover from pinned artifacts")?;

        // Partial batches are fine: PublicBatchProver::commit pads with the
        // pinned dummy private-batch proof template (no shuffle — forwarding
        // stays order-preserving so the chain can attribute each segment to
        // its inner proof).
        let proof = prover
            .commit(PublicBatchInputs {
                proofs,
                aggregator_address: self.aggregator_address,
            })
            .context("failed to commit private-batch proofs to public-batch prover")
            .and_then(|committed| committed.prove().context("public-batch proving failed"))?;

        self.verify(proof.clone())
            .context("proved public-batch proof rejected by the aggregator's pinned verifier")?;
        Ok(proof)
    }

    /// Per-bucket statistics for the operator's "when to aggregate what" policy.
    pub fn bucket_stats(&self) -> Vec<BucketStats> {
        self.pool.bucket_stats()
    }

    /// Total number of pooled proofs.
    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    /// Proofs per public batch (how many one `snapshot_batch`/`aggregate` proves).
    pub fn batch_size(&self) -> usize {
        self.pool.batch_size()
    }

    /// Evict every pooled proof with a nullifier in `settled`, returning the
    /// number evicted. Call on every imported block so proofs settled by other
    /// miners (directly or via a competing public batch) stop occupying batch
    /// slots. See [`ProofPool::evict_settled`].
    pub fn evict_settled(&mut self, settled: &HashSet<BytesDigest>) -> usize {
        self.pool.evict_settled(settled)
    }

    /// Evict every pooled proof admitted more than `max_age` ago, returning
    /// the number evicted. Settlement only reclaims proofs whose nullifiers
    /// reach the chain, so operators MUST run this (or their own expiry
    /// policy) on a cadence with a `max_age` past the chain's acceptance
    /// window — otherwise proofs that lost their inclusion race occupy
    /// `max_proofs` forever. See [`ProofPool::evict_older_than`].
    pub fn evict_older_than(&mut self, max_age: std::time::Duration) -> usize {
        self.pool.evict_older_than(max_age)
    }

    /// Remove one bucket entirely, returning its proofs (operator recovery /
    /// expiry path).
    pub fn remove_bucket(&mut self, key: &BatchKey) -> Vec<Proof> {
        self.pool.remove_bucket(key)
    }

    /// Verify an aggregated public-batch proof produced under this aggregator's
    /// address.
    pub fn verify(&self, proof: Proof) -> Result<()> {
        // Bind the proof's exposed aggregator address to the configured one before
        // accepting it: the public-batch circuit exposes the address as a public
        // input, so without this check a valid proof produced under a different
        // aggregator identity would be accepted here (#96981).
        ensure_proof_public_input_len(
            &proof,
            self.verifier.common.num_public_inputs,
            "public-batch proof",
        )?;
        let proof_aggregator_address =
            try_4_felts_to_bytes(&proof.public_inputs[..AGGREGATOR_ADDRESS_LEN])
                .context("failed to parse public-batch aggregator address from proof")?;
        if proof_aggregator_address != self.aggregator_address {
            bail!(
                "public-batch proof aggregator address {:?} does not match configured aggregator address {:?}",
                proof_aggregator_address,
                self.aggregator_address
            );
        }
        self.verifier
            .verify(proof)
            .map_err(|e| anyhow!("public-batch aggregated proof verification failed: {}", e))
    }

    /// Common circuit data of the public-batch (output) circuit.
    pub fn public_batch_common(&self) -> &CommonCircuitData<F, D> {
        &self.verifier.common
    }

    /// Common circuit data of the private-batch (inner) circuit, e.g. for
    /// deserializing client proof submissions.
    pub fn private_batch_common(&self) -> &CommonCircuitData<F, D> {
        &self.private_batch_verifier.common
    }
}
