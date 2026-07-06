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
    circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
    proof::ProofWithPublicInputs,
};
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_inputs::BytesDigest;
use std::path::{Path, PathBuf};

use std::fs;

use zk_circuits_common::circuit::{C, D, F};

use crate::public_batch::prover::{PublicBatchInputs, PublicBatchProver};
use crate::{
    common::utils::{ensure_proof_public_input_len, leaf_proof_asset_id},
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

fn load_common_from_bins<P: AsRef<Path>>(
    bins_dir: P,
    common_file: &str,
) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = fs::read(bins_dir.as_ref().join(common_file)).with_context(|| {
        format!(
            "failed to read {}",
            bins_dir.as_ref().join(common_file).display()
        )
    })?;
    CommonCircuitData::from_bytes(common_bytes, &gate_serializer)
        .map_err(|e| anyhow!("failed to deserialize {}: {}", common_file, e))
}

fn load_verifier_from_bins(
    bins_dir: &Path,
    common_file: &str,
    verifier_file: &str,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = fs::read(bins_dir.join(common_file))
        .with_context(|| format!("failed to read {}", bins_dir.join(common_file).display()))?;
    let common = CommonCircuitData::from_bytes(common_bytes, &gate_serializer)
        .map_err(|e| anyhow!("failed to deserialize {}: {}", common_file, e))?;

    let verifier_bytes = fs::read(bins_dir.join(verifier_file))
        .with_context(|| format!("failed to read {}", bins_dir.join(verifier_file).display()))?;
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_bytes)
        .map_err(|e| anyhow!("failed to deserialize {}: {}", verifier_file, e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
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

    /// Drain exactly `n` proofs from the front (error if insufficient).
    fn drain_exact(&mut self, n: usize) -> Result<Vec<Proof>> {
        if self.buf.len() < n {
            bail!(
                "not enough proofs buffered (have {}, need {})",
                self.buf.len(),
                n
            );
        }
        Ok(self.buf.drain(0..n).collect())
    }
}

// ============================================================================
// Layer 1 backend (delegated aggregation)
// ============================================================================

pub struct PublicBatchAggregator {
    bins_dir: PathBuf,
    aggregator_address: BytesDigest,
    buf: ProofBuffer,
    expected_private_batch_pi_len: usize,
}

impl PublicBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P, aggregator_address: BytesDigest) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;

        let num_private_batch_proofs = config
            .num_private_batch_proofs
            .ok_or_else(|| anyhow!("config is missing num_private_batch_proofs. Please regenerate the binaries and set \"num_private_batch_proofs\""))?;
        let expected_private_batch_pi_len =
            load_common_from_bins(&bins_dir, "private_batch_common.bin")?.num_public_inputs;

        Ok(Self {
            bins_dir,
            aggregator_address,
            buf: ProofBuffer::new(num_private_batch_proofs),
            expected_private_batch_pi_len,
        })
    }

    fn load_verifier(&self) -> Result<VerifierCircuitData<F, C, D>> {
        load_verifier_from_bins(&self.bins_dir, "public_batch_common.bin", "public_batch_verifier.bin")
    }
}

impl AggregationBackend for PublicBatchAggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(
            &proof,
            self.expected_private_batch_pi_len,
            "private-batch aggregated proof",
        )?;
        self.buf.push(proof)
    }

    fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn batch_size(&self) -> usize {
        self.buf.cap()
    }

    fn aggregate(&mut self) -> Result<Proof> {
        if self.buf.len() == 0 {
            bail!("there are no private-batch proofs to aggregate");
        }

        // Partial batches are fine: PublicBatchProver::commit pads with the dummy
        // private-batch proof template (no shuffle - forwarding stays order-preserving
        // so the chain can attribute each segment to its inner proof).
        let batch = self.buf.take_all();

        // Load the public-batch prover
        let prover = PublicBatchProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt public-batch prover")?;

        let prover = prover
            .commit(PublicBatchInputs {
                proofs: batch,
                aggregator_address: self.aggregator_address,
            })
            .context("failed to commit private-batch proofs to public-batch prover")?;

        prover.prove().context("public-batch proving failed")
    }

    fn verify(&self, proof: Proof) -> Result<()> {
        let verifier = self.load_verifier()?;
        verifier
            .verify(proof)
            .map_err(|e| anyhow!("public-batch aggregated proof verification failed: {}", e))
    }

    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>> {
        let common_file = match circuit_type {
            CircuitType::Root => "public_batch_common.bin",
            CircuitType::Leaf => "private_batch_common.bin",
        };

        load_common_from_bins(&self.bins_dir, common_file)
    }
}

// ============================================================================
// Layer 0 backend (client-side aggregation)
// ============================================================================

pub struct PrivateBatchAggregator {
    bins_dir: PathBuf,
    buf: ProofBuffer,
    expected_leaf_pi_len: usize,
}

impl PrivateBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;
        let expected_leaf_pi_len =
            load_common_from_bins(&bins_dir, "common.bin")?.num_public_inputs;

        Ok(Self {
            bins_dir,
            buf: ProofBuffer::new(config.num_leaf_proofs),
            expected_leaf_pi_len,
        })
    }

    fn build_prover(&self) -> Result<PrivateBatchProver> {
        PrivateBatchProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt private-batch prover from binaries dir")
    }

    fn load_verifier(&self) -> Result<VerifierCircuitData<F, C, D>> {
        load_verifier_from_bins(
            &self.bins_dir,
            "private_batch_common.bin",
            "private_batch_verifier.bin",
        )
    }
}

impl AggregationBackend for PrivateBatchAggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(&proof, self.expected_leaf_pi_len, "leaf proof")?;
        self.buf.push(proof)
    }

    fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn batch_size(&self) -> usize {
        self.buf.cap()
    }

    fn aggregate(&mut self) -> Result<Proof> {
        if self.buf.len() == 0 {
            bail!("there are no leaf proofs to aggregate");
        }

        // Private-batch prover commit does padding/shuffling/dummy-nullifier-preimage handling,
        // so we can pass any non-empty batch. The wrapper's same-block / same-asset invariants are
        // intentional protocol rules and remain enforced in-circuit; this preflight only rejects
        // malformed or dummy-padding-incompatible inputs earlier.
        let proofs = self.buf.take_all();
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
        let prover = prover
            .commit(proofs)
            .context("failed to commit leaf proofs to private-batch aggregation prover")?;

        prover.prove().context("private-batch proving failed")
    }

    fn verify(&self, proof: Proof) -> Result<()> {
        let verifier = self.load_verifier()?;
        verifier
            .verify(proof)
            .map_err(|e| anyhow!("private-batch aggregated proof verification failed: {}", e))
    }

    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>> {
        let common_file = match circuit_type {
            CircuitType::Root => "private_batch_common.bin",
            CircuitType::Leaf => "common.bin",
        };

        load_common_from_bins(&self.bins_dir, common_file)
    }
}
