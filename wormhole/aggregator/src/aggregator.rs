//! High-level aggregation orchestrator.
//!
//! Responsibilities:
//! - Buffer leaf proofs
//! - Invoke the prebuilt layer-0 aggregation prover
//! - Optionally buffer layer-0 aggregated proofs and delegate to a layer-1 backend
//!
//! IMPORTANT:
//! Padding with dummies, shuffling, and dummy-nullifier generation are handled
//! inside `layer0::prover::Layer0AggregationProver::commit(...)`.
//! The orchestrator intentionally does NOT duplicate that logic.

// TODO connect layer 2 backend
use anyhow::{anyhow, bail, Context, Result};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
    proof::ProofWithPublicInputs,
    // 👇 add these if not already in scope in your crate version
    // (they're only needed for loading prebuilt verifier/common bytes)
};
use plonky2::util::serialization::DefaultGateSerializer;
use std::path::{Path, PathBuf};

#[cfg(feature = "std")]
use std::fs;

use zk_circuits_common::{
    aggregation::AggregationConfig,
    circuit::{C, D, F},
};

use crate::layer0::{
    circuit::circuit_logic::Layer0AggregationCircuit,
    prover::{Layer0AggregationInputs, Layer0AggregationProver},
};

/// Optional abstraction for delegated layer-1 aggregation.
///
/// You can implement this later with your prebuilt `layer1::prover::...`.
pub trait Layer1AggregationBackend: Send + Sync {
    /// Aggregate a batch of layer-0 aggregated proofs into a single higher-level proof.
    fn aggregate(
        &self,
        layer0_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>>;

    /// Recommended batch size for this backend (orchestrator can use this to decide when to flush).
    fn batch_size(&self) -> usize;
}

/// High-level wormhole aggregation orchestrator.
///
/// Buffers leaf proofs, then hands them to the prebuilt layer-0 prover when ready.
/// The returned layer-0 proof can be buffered for a future layer-1 backend.
pub struct WormholeAggregator {
    /// The directory that contains all the prebuilt circuit artifacts (layer-0 + leaf).
    /// DEV NOTE: we could optionally support separate paths for layer-0 vs leaf artifacts,
    /// but this is simpler for now since the layer-0 build already depends on the leaf common data.
    pub bin_dir: PathBuf,

    /// Public config (kept public for compatibility with older tests/code).
    pub config: AggregationConfig,

    /// Buffer of leaf proofs waiting to be aggregated into one layer-0 proof.
    pub leaf_proofs_buffer: Vec<ProofWithPublicInputs<F, C, D>>,

    /// Optional buffer of layer-0 aggregated proofs (used when layer1 backend is configured).
    layer0_buffer: Vec<ProofWithPublicInputs<F, C, D>>,

    /// Optional layer-1 backend.
    layer1_backend: Option<Box<dyn Layer1AggregationBackend>>,
}

impl WormholeAggregator {
    /// Create an orchestrator from a directory with prebuilt binaries.
    ///
    /// Expected layer-0 files:
    /// - `aggregated_prover.bin`
    /// - `aggregated_common.bin`
    /// - `layer0_targets.json`
    ///
    /// Expected leaf files:
    /// - `common.bin`
    /// - `verifier.bin`
    /// - `dummy_proof.bin`
    ///
    /// If `config.json` exists, hash verification is performed by
    /// `Layer0AggregationProver::new_from_binaries_dir(...)`.
    pub fn from_binaries_dir<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load once to discover configured batch size (and verify hashes if config.json exists).
        let layer0_prover = Layer0AggregationProver::new_from_binaries_dir(&bins_dir)
            .context("failed to load prebuilt layer-0 aggregation prover")?;

        let config = AggregationConfig::new(layer0_prover.num_leaf_proofs());

        Ok(Self {
            bin_dir: bins_dir,
            leaf_proofs_buffer: Vec::with_capacity(config.num_leaf_proofs),
            layer0_buffer: Vec::new(),
            layer1_backend: None,
            config,
        })
    }

    /// Attach a layer-1 backend for delegated higher-level aggregation.
    pub fn with_layer1_backend(mut self, backend: Box<dyn Layer1AggregationBackend>) -> Self {
        self.layer1_backend = Some(backend);
        self
    }

    /// Number of leaf proofs currently buffered.
    pub fn leaf_buffer_len(&self) -> usize {
        self.leaf_proofs_buffer.len()
    }

    /// Number of layer-0 aggregated proofs currently buffered.
    pub fn layer0_buffer_len(&self) -> usize {
        self.layer0_buffer.len()
    }

    /// Layer-0 batch capacity (number of leaf proofs per aggregate).
    pub fn num_leaf_proofs(&self) -> usize {
        self.config.num_leaf_proofs
    }

    /// Backwards-compatible alias for older call sites.
    pub fn push_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.push_leaf_proof(proof)
    }

    /// Push a leaf proof into the layer-0 buffer.
    ///
    /// Returns an error if the buffer is already full (exactly `num_leaf_proofs`).
    pub fn push_leaf_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        if self.leaf_proofs_buffer.len() >= self.config.num_leaf_proofs {
            bail!(
                "layer-0 leaf buffer is full (capacity = {})",
                self.config.num_leaf_proofs
            );
        }

        self.leaf_proofs_buffer.push(proof);
        Ok(())
    }

    /// Aggregate the currently buffered leaf proofs into one layer-0 aggregated proof.
    ///
    /// Behavior:
    /// - Requires at least 1 proof in the buffer
    /// - Delegates padding/shuffling/dummy-nullifier handling to `Layer0AggregationProver::commit`
    /// - Clears the leaf buffer on success
    pub fn aggregate_layer0(&mut self) -> Result<ProofWithPublicInputs<F, C, D>> {
        if self.leaf_proofs_buffer.is_empty() {
            bail!("there are no leaf proofs to aggregate");
        }

        // Move proofs out of the buffer (the prover takes ownership).
        let proofs = std::mem::take(&mut self.leaf_proofs_buffer);

        // Fresh prover instance (from binaries OR in-memory config path).
        let prover = self
            .build_layer0_prover()
            .context("failed to create layer-0 aggregation prover")?;

        // Commit handles:
        // - padding with dummies
        // - shuffling while preserving a real proof in slot 0
        // - dummy nullifier generation
        let prover = prover
            .commit(Layer0AggregationInputs { proofs })
            .context("failed to commit leaf proofs to layer-0 aggregation prover")?;

        let proof = prover.prove().context("layer-0 proving failed")?;

        Ok(proof)
    }

    /// Backwards-compatible alias for older call sites that used `aggregate()`.
    pub fn aggregate(&mut self) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.aggregate_layer0()
    }

    /// Verify a layer-0 aggregated proof against the orchestrator's configured circuit.
    ///
    /// - In `from_binaries_dir(...)` mode, this loads the prebuilt aggregated verifier/common files.
    /// - In `from_circuit_config(...)` mode, this rebuilds the layer-0 verifier circuit in memory.
    pub fn verify_aggregated_proof(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        let verifier = self
            .build_layer0_verifier()
            .context("failed to build/load layer-0 verifier")?;

        verifier
            .verify(proof)
            .map_err(|e| anyhow!("layer-0 aggregated proof verification failed: {}", e))
    }

    /// Convenience method: aggregate layer-0 and immediately push the result to the layer-1 buffer.
    pub fn aggregate_layer0_into_layer1_buffer(&mut self) -> Result<()> {
        let l0 = self.aggregate_layer0()?;
        self.layer0_buffer.push(l0);
        Ok(())
    }

    /// Push an externally produced layer-0 aggregated proof into the layer-1 buffer.
    pub fn push_layer0_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) {
        self.layer0_buffer.push(proof);
    }

    /// Try to aggregate the buffered layer-0 proofs using the configured layer-1 backend.
    ///
    /// Returns:
    /// - `Ok(None)` if no layer-1 backend is configured
    /// - `Ok(None)` if there aren't enough buffered proofs yet
    /// - `Ok(Some(proof))` when a layer-1 aggregation was produced
    pub fn try_aggregate_layer1(&mut self) -> Result<Option<ProofWithPublicInputs<F, C, D>>> {
        let Some(backend) = self.layer1_backend.as_ref() else {
            return Ok(None);
        };

        let batch_size = backend.batch_size();
        if self.layer0_buffer.len() < batch_size {
            return Ok(None);
        }

        let batch = self.layer0_buffer.drain(0..batch_size).collect::<Vec<_>>();
        let out = backend.aggregate(batch)?;
        Ok(Some(out))
    }

    /// Clear all in-memory buffers (leaf + layer0).
    pub fn clear_buffers(&mut self) {
        self.leaf_proofs_buffer.clear();
        self.layer0_buffer.clear();
    }

    /// Internal helper: build a fresh layer-0 prover from the configured source.
    fn build_layer0_prover(&self) -> Result<Layer0AggregationProver> {
        Layer0AggregationProver::new_from_binaries_dir(&self.bin_dir)
            .context("failed to load prebuilt layer-0 prover from binaries dir")
    }

    /// Internal helper: build/load the layer-0 verifier circuit.
    fn build_layer0_verifier(&self) -> Result<VerifierCircuitData<F, C, D>> {
        // Optional integrity verification (same pattern as prover path).
        let config_path = self.bin_dir.join("config.json");
        if config_path.exists() {
            let bins_config = crate::config::CircuitBinsConfig::load(&self.bin_dir)?;
            bins_config.verify_hashes(&self.bin_dir)?;
        }

        let gate_serializer = DefaultGateSerializer;

        let aggregated_common_bytes = fs::read(self.bin_dir.join("aggregated_common.bin"))
            .context("failed to read aggregated_common.bin")?;
        let common = CommonCircuitData::from_bytes(aggregated_common_bytes, &gate_serializer)
            .map_err(|e| {
                anyhow!(
                    "failed to deserialize aggregated common circuit data: {}",
                    e
                )
            })?;

        let aggregated_verifier_bytes = fs::read(self.bin_dir.join("aggregated_verifier.bin"))
            .context("failed to read aggregated_verifier.bin")?;
        let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(aggregated_verifier_bytes)
            .map_err(|e| {
                anyhow!(
                    "failed to deserialize aggregated verifier circuit data: {}",
                    e
                )
            })?;

        Ok(VerifierCircuitData {
            verifier_only,
            common,
        })
    }
}
