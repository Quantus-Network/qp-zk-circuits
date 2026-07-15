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
//! Public-batch proving takes minutes. [`PublicBatchAggregator::aggregate`] is
//! the simple blocking convenience; a service that must keep admitting proofs
//! while proving should split the phases and only lock around the cheap pool
//! operations:
//!
//! ```text
//! // admission thread, short lock:
//! let taken = aggregator.lock().take_batch(&key);
//!
//! // proving worker, NO lock held (use its own prover instance):
//! let prover = PublicBatchProver::new_from_binaries_dir(&bins_dir)?;
//! let result = prover
//!     .commit(PublicBatchInputs { proofs: taken.proofs(), aggregator_address })?
//!     .prove();
//!
//! // back under a short lock:
//! match result {
//!     Ok(proof) => drop(taken), // proofs consumed; submit `proof`
//!     Err(_) => { aggregator.lock().reinsert_batch(taken); }
//! }
//! ```
//!
//! Buckets queue deeper than one batch, so admissions for the same key keep
//! landing while its previous batch is out being proved. Reinserted proofs are
//! not re-verified, and proofs that settled on-chain while out are cleaned up
//! by the regular [`PublicBatchAggregator::evict_settled`] cadence.

use anyhow::{anyhow, bail, Context, Result};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierCircuitData},
    proof::ProofWithPublicInputs,
};
use qp_wormhole_inputs::{public_batch_pi::AGGREGATOR_ADDRESS_LEN, BytesDigest};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::try_4_felts_to_bytes,
};

use crate::pool::{BatchKey, BucketStats, PoolLimits, ProofPool, TakenBatch};
use crate::public_batch::prover::{PublicBatchInputs, PublicBatchProver};
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
    fs::read(bins_dir.join(file))
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
    bins_dir: PathBuf,
    aggregator_address: BytesDigest,
    pool: ProofPool,
    /// Canonical-pinned public-batch verifier data, loaded once at construction.
    verifier: VerifierCircuitData<F, C, D>,
    /// Canonical-pinned private-batch (inner) common data, kept for proof
    /// deserialization by callers.
    private_batch_common: CommonCircuitData<F, D>,
}

impl PublicBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P, aggregator_address: BytesDigest) -> Result<Self> {
        Self::with_limits(bins_dir, aggregator_address, PoolLimits::default())
    }

    pub fn with_limits<P: AsRef<Path>>(
        bins_dir: P,
        aggregator_address: BytesDigest,
        limits: PoolLimits,
    ) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        let config = CircuitBinsConfig::load(&bins_dir)?;
        let num_private_batch_proofs = config
            .num_private_batch_proofs
            .ok_or_else(|| anyhow!("config is missing num_private_batch_proofs. Please regenerate the binaries and set \"num_private_batch_proofs\""))?;
        let num_leaf_proofs = config.num_leaf_proofs;

        let private_batch = load_private_batch_verifier_from_bins(&bins_dir, num_leaf_proofs)?;
        let verifier = load_public_batch_verifier_from_bins(
            &bins_dir,
            &private_batch,
            num_leaf_proofs,
            num_private_batch_proofs,
        )?;

        let private_batch_common = private_batch.common.clone();
        let pool = ProofPool::new(
            private_batch,
            num_leaf_proofs,
            num_private_batch_proofs,
            limits,
        )?;

        Ok(Self {
            bins_dir,
            aggregator_address,
            pool,
            verifier,
            private_batch_common,
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
    /// Only the proofs actually proved are drained, and only on success; a
    /// failed attempt reinserts them for retry without re-verification
    /// (#97067). Proofs beyond `batch_size` stay queued for the next call.
    ///
    /// This convenience method holds `&mut self` for the entire (minutes-long)
    /// proving run, so a lock-wrapped aggregator admits nothing meanwhile. A
    /// concurrent service should use the split API instead: [`Self::take_batch`]
    /// under a short lock, [`Self::prove_taken`] on a proving worker WITHOUT
    /// holding the lock, then drop the batch on success or
    /// [`Self::reinsert_batch`] on failure.
    pub fn aggregate(&mut self, key: &BatchKey) -> Result<Proof> {
        let Some(taken) = self.pool.take_batch(key) else {
            bail!(
                "no pooled proofs for block {:?} (asset {}, fee {})",
                key.block_hash,
                key.asset_id,
                key.volume_fee_bps
            );
        };

        match self.prove_taken(&taken) {
            Ok(proof) => Ok(proof),
            Err(e) => {
                self.pool.reinsert(taken);
                Err(e)
            }
        }
    }

    /// Remove up to `batch_size` of the oldest proofs for `key` from the pool,
    /// for proving via [`Self::prove_taken`]. Cheap; see [`ProofPool::take_batch`].
    pub fn take_batch(&mut self, key: &BatchKey) -> Option<TakenBatch> {
        self.pool.take_batch(key)
    }

    /// Restore a taken batch after a failed proving attempt (no cryptographic
    /// re-verification). Returns the number of proofs restored; see
    /// [`ProofPool::reinsert`].
    pub fn reinsert_batch(&mut self, batch: TakenBatch) -> usize {
        self.pool.reinsert(batch)
    }

    /// Prove a taken batch into a public-batch proof bound to this
    /// aggregator's address. Does not touch the pool.
    ///
    /// Takes minutes. In a concurrent service, run this on a dedicated proving
    /// worker without holding whatever lock guards the aggregator — either via
    /// a separately constructed [`PublicBatchProver`] fed `batch.proofs()`, or
    /// by cheaply cloning the `TakenBatch`-relevant state out of the lock.
    pub fn prove_taken(&self, batch: &TakenBatch) -> Result<Proof> {
        let prover = PublicBatchProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt public-batch prover")?;

        // Partial batches are fine: PublicBatchProver::commit pads with the dummy
        // private-batch proof template (no shuffle - forwarding stays order-preserving
        // so the chain can attribute each segment to its inner proof).
        prover
            .commit(PublicBatchInputs {
                proofs: batch.proofs(),
                aggregator_address: self.aggregator_address,
            })
            .context("failed to commit private-batch proofs to public-batch prover")
            .and_then(|committed| committed.prove().context("public-batch proving failed"))
    }

    /// Per-bucket statistics for the operator's "when to aggregate what" policy.
    pub fn bucket_stats(&self) -> Vec<BucketStats> {
        self.pool.bucket_stats()
    }

    /// Total number of pooled proofs.
    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    /// Proofs per public batch (how many one `take_batch`/`aggregate` proves).
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
        &self.private_batch_common
    }
}
