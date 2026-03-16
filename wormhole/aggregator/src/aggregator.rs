//! High-level aggregation orchestrator backends.
//!
//! - Layer0Aggregator: client/privacy-preserving aggregation (pads/shuffles inside Layer0AggregationProver::commit).
//! - Layer1Aggregator: delegated aggregation ( expects full batches of layer-0 proofs).
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

use crate::layer1::prover::{Layer1AggregationInputs, Layer1AggregationProver};
use crate::{
    common::utils::{ensure_proof_public_input_len, leaf_proof_asset_id},
    layer0::prover::{Layer0AggregationInputs, Layer0AggregationProver},
    CircuitBinsConfig,
};

type Proof = ProofWithPublicInputs<F, C, D>;
pub enum CircuitType {
    Root,
    Leaf,
}

/// Generic trait that both layer-0 and layer-1 backends implement.
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

pub struct Layer1Aggregator {
    bins_dir: PathBuf,
    aggregator_address: BytesDigest,
    buf: ProofBuffer,
    expected_layer0_pi_len: usize,
}

impl Layer1Aggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P, aggregator_address: BytesDigest) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;

        let num_layer0_proofs = config
            .num_layer0_proofs
            .ok_or_else(|| anyhow!("config is missing num_layer0_proofs. Please regenerate the binaries and set \"num_layer0_proofs\""))?;
        let expected_layer0_pi_len =
            load_common_from_bins(&bins_dir, "aggregated_common.bin")?.num_public_inputs;

        Ok(Self {
            bins_dir,
            aggregator_address,
            buf: ProofBuffer::new(num_layer0_proofs),
            expected_layer0_pi_len,
        })
    }

    fn load_verifier(&self) -> Result<VerifierCircuitData<F, C, D>> {
        load_verifier_from_bins(&self.bins_dir, "layer1_common.bin", "layer1_verifier.bin")
    }
}

impl AggregationBackend for Layer1Aggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(
            &proof,
            self.expected_layer0_pi_len,
            "layer-0 aggregated proof",
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
        let cap = self.batch_size();

        // We require a full batch for layer1. No padding allowed
        let batch = self
            .buf
            .drain_exact(cap)
            .with_context(|| "No dummy padding for layer-1: need a full batch of layer-0 proofs")?;

        // Load the layer-1 prover
        let prover = Layer1AggregationProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt layer-1 prover")?;

        let prover = prover
            .commit(Layer1AggregationInputs {
                proofs: batch,
                aggregator_address: self.aggregator_address,
            })
            .context("failed to commit layer-0 proofs to layer-1 prover")?;

        prover.prove().context("layer-1 proving failed")
    }

    fn verify(&self, proof: Proof) -> Result<()> {
        let verifier = self.load_verifier()?;
        verifier
            .verify(proof)
            .map_err(|e| anyhow!("layer-1 aggregated proof verification failed: {}", e))
    }

    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>> {
        let common_file = match circuit_type {
            CircuitType::Root => "layer1_common.bin",
            CircuitType::Leaf => "aggregated_common.bin",
        };

        load_common_from_bins(&self.bins_dir, common_file)
    }
}

// ============================================================================
// Layer 0 backend (client-side aggregation)
// ============================================================================

pub struct Layer0Aggregator {
    bins_dir: PathBuf,
    buf: ProofBuffer,
    expected_leaf_pi_len: usize,
}

impl Layer0Aggregator {
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

    fn build_prover(&self) -> Result<Layer0AggregationProver> {
        Layer0AggregationProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt layer-0 prover from binaries dir")
    }

    fn load_verifier(&self) -> Result<VerifierCircuitData<F, C, D>> {
        load_verifier_from_bins(
            &self.bins_dir,
            "aggregated_common.bin",
            "aggregated_verifier.bin",
        )
    }
}

impl AggregationBackend for Layer0Aggregator {
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

        // Layer-0 prover commit does padding/shuffling/dummy-nullifier-preimage handling,
        // so we can pass any non-empty batch. The wrapper's same-block / same-asset invariants are
        // intentional protocol rules and remain enforced in-circuit; this preflight only rejects
        // malformed or dummy-padding-incompatible inputs earlier.
        let proofs = self.buf.take_all();
        if proofs.len() < self.batch_size() {
            for (idx, proof) in proofs.iter().enumerate() {
                let asset_id = leaf_proof_asset_id(proof)?;
                if asset_id != 0 {
                    bail!(
                        "proof {} has asset_id={}, but layer-0 dummy padding requires all real proofs to use asset_id=0",
                        idx,
                        asset_id
                    );
                }
            }
        }

        let prover = self.build_prover()?;
        let prover = prover
            .commit(Layer0AggregationInputs { proofs })
            .context("failed to commit leaf proofs to layer-0 aggregation prover")?;

        prover.prove().context("layer-0 proving failed")
    }

    fn verify(&self, proof: Proof) -> Result<()> {
        let verifier = self.load_verifier()?;
        verifier
            .verify(proof)
            .map_err(|e| anyhow!("layer-0 aggregated proof verification failed: {}", e))
    }

    fn load_common_data(&self, circuit_type: CircuitType) -> Result<CommonCircuitData<F, D>> {
        let common_file = match circuit_type {
            CircuitType::Root => "aggregated_common.bin",
            CircuitType::Leaf => "common.bin",
        };

        load_common_from_bins(&self.bins_dir, common_file)
    }
}
