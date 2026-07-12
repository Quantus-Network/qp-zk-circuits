//! High-level aggregation orchestrator backends.
//!
//! - PrivateBatchAggregator: client/privacy-preserving aggregation (pads/shuffles inside PrivateBatchProver::commit).
//! - PublicBatchAggregator: delegated aggregation ( expects full batches of private-batch proofs).
//!
//! Shared utilities:
//! - verifier loading from {common.bin, verifier.bin}
//! - bounded proof buffers

use anyhow::{anyhow, bail, Context, Result};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierCircuitData},
    proof::ProofWithPublicInputs,
};
use qp_wormhole_inputs::{public_batch_pi::AGGREGATOR_ADDRESS_LEN, BytesDigest};
use std::path::{Path, PathBuf};

use std::fs;

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::try_4_felts_to_bytes,
};

use crate::public_batch::prover::{PublicBatchInputs, PublicBatchProver};
use crate::{
    common::utils::{
        canonical_leaf_verifier_data, canonical_public_batch_verifier_data,
        ensure_proof_public_input_len, ensure_verifier_data_matches_canonical, leaf_proof_asset_id,
        load_canonical_leaf_verifier_data, load_canonical_private_batch_verifier_data,
        load_verifier_data_from_bytes,
    },
    private_batch::prover::PrivateBatchProver,
    CircuitBinsConfig,
};

type Proof = ProofWithPublicInputs<F, C, D>;
pub enum CircuitType {
    Root,
    Leaf,
}

/// Generic trait that both private-batch and public-batch backends implement.
pub trait AggregationBackend: Send + Sync {
    /// Push a proof into the backend's internal buffer.
    fn push_proof(&mut self, proof: Proof) -> Result<()>;

    /// Current number of proofs buffered.
    fn buffer_len(&self) -> usize;

    /// Batch size (capacity) for this backend.
    fn batch_size(&self) -> usize;

    /// Aggregate buffered proofs into a single proof.
    fn aggregate(&mut self) -> Result<Proof>;

    /// Verify an aggregated proof produced by this backend.
    fn verify(&self, _proof: Proof) -> Result<()> {
        bail!("this aggregation backend does not implement verification")
    }

    /// Load common circuit data for this backend's circuit type (leaf or root).
    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>>;
}

// ============================================================================
// Shared helpers
// ============================================================================

fn read_bin(bins_dir: &Path, file: &str) -> Result<Vec<u8>> {
    fs::read(bins_dir.join(file))
        .with_context(|| format!("failed to read {}", bins_dir.join(file).display()))
}

fn load_leaf_verifier_from_bins(bins_dir: &Path) -> Result<VerifierCircuitData<F, C, D>> {
    load_canonical_leaf_verifier_data(
        &read_bin(bins_dir, "common.bin")?,
        &read_bin(bins_dir, "verifier.bin")?,
    )
}

fn load_private_batch_verifier_from_bins(
    bins_dir: &Path,
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    load_canonical_private_batch_verifier_data(
        &read_bin(bins_dir, "private_batch_common.bin")?,
        &read_bin(bins_dir, "private_batch_verifier.bin")?,
        leaf,
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

/// A small bounded buffer helper so the backends don't duplicate capacity checks / draining logic.
#[derive(Debug)]
struct ProofBuffer {
    cap: usize,
    buf: Vec<Proof>,
}

impl ProofBuffer {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: Vec::with_capacity(cap),
        }
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn cap(&self) -> usize {
        self.cap
    }

    fn push(&mut self, proof: Proof) -> Result<()> {
        if self.buf.len() >= self.cap {
            bail!("proof buffer is full (capacity = {})", self.cap);
        }
        self.buf.push(proof);
        Ok(())
    }

    /// Take all currently buffered proofs (clears buffer).
    fn take_all(&mut self) -> Vec<Proof> {
        std::mem::take(&mut self.buf)
    }

    /// Clone all currently buffered proofs without clearing the buffer.
    ///
    /// Used by the aggregation backends to attempt commit/prove over a copy so
    /// that a failed aggregation leaves the queued proofs intact (#97067).
    fn clone_all(&self) -> Vec<Proof> {
        self.buf.clone()
    }
}

// ============================================================================
// Layer 1 backend (delegated aggregation)
// ============================================================================

pub struct PublicBatchAggregator {
    bins_dir: PathBuf,
    aggregator_address: BytesDigest,
    buf: ProofBuffer,
    /// Canonical-pinned private-batch verifier data (inner proofs), loaded once at construction.
    private_batch_verifier: VerifierCircuitData<F, C, D>,
    /// Canonical-pinned public-batch verifier data, loaded once at construction.
    verifier: VerifierCircuitData<F, C, D>,
}

impl PublicBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P, aggregator_address: BytesDigest) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;

        let num_private_batch_proofs = config
            .num_private_batch_proofs
            .ok_or_else(|| anyhow!("config is missing num_private_batch_proofs. Please regenerate the binaries and set \"num_private_batch_proofs\""))?;
        let num_leaf_proofs = config.num_leaf_proofs;

        let leaf = canonical_leaf_verifier_data();
        let private_batch =
            load_private_batch_verifier_from_bins(&bins_dir, &leaf, num_leaf_proofs)?;
        let verifier = load_public_batch_verifier_from_bins(
            &bins_dir,
            &private_batch,
            num_leaf_proofs,
            num_private_batch_proofs,
        )?;

        Ok(Self {
            bins_dir,
            aggregator_address,
            buf: ProofBuffer::new(num_private_batch_proofs),
            private_batch_verifier: private_batch,
            verifier,
        })
    }
}

impl AggregationBackend for PublicBatchAggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(
            &proof,
            self.private_batch_verifier.common.num_public_inputs,
            "private-batch aggregated proof",
        )?;
        // Verify the proof before queuing it. Since the queue is only drained on
        // successful aggregation (#97067), a single invalid proof accepted here
        // would otherwise make every aggregate() retry fail on the same poisoned
        // batch, wedging the aggregator permanently.
        self.private_batch_verifier
            .verify(proof.clone())
            .map_err(|e| {
                anyhow!(
                    "refusing to queue invalid private-batch proof: verification failed: {}",
                    e
                )
            })?;
        self.buf.push(proof)
    }

    fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn batch_size(&self) -> usize {
        self.buf.cap()
    }

    fn aggregate(&mut self) -> Result<Proof> {
        if self.buf.is_empty() {
            bail!("there are no private-batch proofs to aggregate");
        }

        // Aggregate over a clone of the queue so a failed commit/prove leaves the
        // queued proofs intact for retry instead of dropping them (#97067).
        let batch = self.buf.clone_all();

        // Load the public-batch prover (failures here don't touch the queue).
        let prover = PublicBatchProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt public-batch prover")?;

        // Partial batches are fine: PublicBatchProver::commit pads with the dummy
        // private-batch proof template (no shuffle - forwarding stays order-preserving
        // so the chain can attribute each segment to its inner proof).
        let result = prover
            .commit(PublicBatchInputs {
                proofs: batch,
                aggregator_address: self.aggregator_address,
            })
            .context("failed to commit private-batch proofs to public-batch prover")
            .and_then(|committed| committed.prove().context("public-batch proving failed"));

        if result.is_ok() {
            // Only drain the queue once aggregation fully succeeds.
            let _ = self.buf.take_all();
        }
        result
    }

    fn verify(&self, proof: Proof) -> Result<()> {
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

    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>> {
        match circuit_type {
            CircuitType::Root => Ok(self.verifier.common.clone()),
            CircuitType::Leaf => Ok(self.private_batch_verifier.common.clone()),
        }
    }
}

// ============================================================================
// Layer 0 backend (client-side aggregation)
// ============================================================================

pub struct PrivateBatchAggregator {
    bins_dir: PathBuf,
    buf: ProofBuffer,
    /// Canonical-pinned leaf verifier data, loaded once at construction.
    leaf_verifier: VerifierCircuitData<F, C, D>,
    /// Canonical-pinned private-batch verifier data, loaded once at construction.
    verifier: VerifierCircuitData<F, C, D>,
}

impl PrivateBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;
        let num_leaf_proofs = config.num_leaf_proofs;

        let leaf = load_leaf_verifier_from_bins(&bins_dir)?;
        let verifier = load_private_batch_verifier_from_bins(&bins_dir, &leaf, num_leaf_proofs)?;

        Ok(Self {
            bins_dir,
            buf: ProofBuffer::new(num_leaf_proofs),
            leaf_verifier: leaf,
            verifier,
        })
    }

    fn build_prover(&self) -> Result<PrivateBatchProver> {
        PrivateBatchProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt private-batch prover from binaries dir")
    }
}

impl AggregationBackend for PrivateBatchAggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(
            &proof,
            self.leaf_verifier.common.num_public_inputs,
            "leaf proof",
        )?;
        // Verify the proof before queuing it. Since the queue is only drained on
        // successful aggregation (#97067), a single invalid proof accepted here
        // would otherwise make every aggregate() retry fail on the same poisoned
        // batch, wedging the aggregator permanently.
        self.leaf_verifier.verify(proof.clone()).map_err(|e| {
            anyhow!(
                "refusing to queue invalid leaf proof: verification failed: {}",
                e
            )
        })?;
        self.buf.push(proof)
    }

    fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn batch_size(&self) -> usize {
        self.buf.cap()
    }

    fn aggregate(&mut self) -> Result<Proof> {
        if self.buf.is_empty() {
            bail!("there are no leaf proofs to aggregate");
        }

        // Aggregate over a clone of the queue so a failed preflight/commit/prove
        // leaves the queued proofs intact for retry instead of dropping them (#97067).
        let proofs = self.buf.clone_all();

        // Private-batch prover commit does padding/shuffling/dummy-nullifier-preimage handling,
        // so we can pass any non-empty batch. The wrapper's same-block / same-asset invariants are
        // intentional protocol rules and remain enforced in-circuit; this preflight only rejects
        // malformed or dummy-padding-incompatible inputs earlier.
        if proofs.len() < self.batch_size() {
            for (idx, proof) in proofs.iter().enumerate() {
                let asset_id = leaf_proof_asset_id(proof)?;
                if asset_id != 0 {
                    bail!(
                        "proof {} has asset_id={}, but private-batch dummy padding requires all real proofs to use asset_id=0",
                        idx,
                        asset_id
                    );
                }
            }
        }

        let prover = self.build_prover()?;
        let result = prover
            .commit(proofs)
            .context("failed to commit leaf proofs to private-batch aggregation prover")
            .and_then(|committed| committed.prove().context("private-batch proving failed"));

        if result.is_ok() {
            // Only drain the queue once aggregation fully succeeds.
            let _ = self.buf.take_all();
        }
        result
    }

    fn verify(&self, proof: Proof) -> Result<()> {
        self.verifier
            .verify(proof)
            .map_err(|e| anyhow!("private-batch aggregated proof verification failed: {}", e))
    }

    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>> {
        match circuit_type {
            CircuitType::Root => Ok(self.verifier.common.clone()),
            CircuitType::Leaf => Ok(self.leaf_verifier.common.clone()),
        }
    }
}
