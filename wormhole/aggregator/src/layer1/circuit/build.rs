//! Build + serialize layer-1 aggregation circuit artifacts.
//!
//! Produces:
//! - `layer1_common.bin`
//! - `layer1_verifier.bin`
//! - `layer1_prover.bin` (optional)
//! - `layer1_targets.json`
//! - `layer1_dummy_proof.bin` (serialized dummy layer-0 aggregated proof for layer-1 padding)
//!
//! Expects layer-0 artifacts to already exist in `output_dir`:
//! - `aggregated_common.bin`
//! - `aggregated_verifier.bin`
//! - `aggregated_prover.bin`
//! - `layer0_targets.json`
//! - `common.bin`
//! - `verifier.bin`
//! - `dummy_proof.bin`

use anyhow::{anyhow, Context, Result};
use std::fs::{create_dir_all, write};
use std::path::Path;

use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};

use zk_circuits_common::circuit::{C, D, F};

use crate::layer0::prover::{Layer0AggregationInputs, Layer0AggregationProver};
use crate::layer1::{
    circuit::circuit_logic::Layer1AggregationCircuit, prover::targets_layout::Layer1TargetsLayoutD,
};

/// Build configuration for the layer-1 circuit.
#[derive(Debug, Clone)]
pub struct Layer1BuildConfig {
    /// Number of layer-0 aggregated proofs to combine in one layer-1 proof.
    pub num_layer0_proofs: usize,
    /// Number of leaf proofs represented in each layer-0 proof.
    pub layer0_num_leaves: usize,
    /// Whether to also emit `layer1_prover.bin`.
    pub include_prover: bool,
    /// Circuit config for the layer-1 circuit.
    pub circuit_config: CircuitConfig,
}

impl Layer1BuildConfig {
    pub fn new(num_layer0_proofs: usize, layer0_num_leaves: usize) -> Self {
        Self {
            num_layer0_proofs,
            layer0_num_leaves,
            include_prover: true,
            circuit_config: CircuitConfig::standard_recursion_zk_config(),
        }
    }

    pub fn with_include_prover(mut self, include_prover: bool) -> Self {
        self.include_prover = include_prover;
        self
    }

    pub fn with_circuit_config(mut self, circuit_config: CircuitConfig) -> Self {
        self.circuit_config = circuit_config;
        self
    }
}

/// Build and write all layer-1 artifacts into `output_dir`.
///
/// This assumes layer-0 artifacts are already present in `output_dir`.
pub fn build_layer1_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    cfg: Layer1BuildConfig,
) -> Result<()> {
    let output_dir = output_dir.as_ref();
    create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    // -------------------------------------------------------------------------
    // 1) Load layer-0 common circuit data (child circuit for layer-1)
    // -------------------------------------------------------------------------
    let layer0_common = load_layer0_common_from_bins(output_dir)
        .context("Failed to load layer-0 common circuit data from bins dir")?;

    // -------------------------------------------------------------------------
    // 2) Build layer-1 circuit + targets layout
    // -------------------------------------------------------------------------
    let layer1_circuit = Layer1AggregationCircuit::new(
        cfg.circuit_config.clone(),
        layer0_common,
        cfg.num_layer0_proofs,
        cfg.layer0_num_leaves,
    );

    let targets = layer1_circuit.targets();
    let targets_layout = Layer1TargetsLayoutD::from(&targets);
    let targets_layout_bytes = targets_layout
        .to_bytes()
        .context("Failed to serialize layer1 targets layout")?;

    write(output_dir.join("layer1_targets.json"), targets_layout_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            output_dir.join("layer1_targets.json").display()
        )
    })?;

    // -------------------------------------------------------------------------
    // 3) Build verifier artifacts (common + verifier)
    // -------------------------------------------------------------------------
    let verifier_data = layer1_circuit.build_verifier();
    write_verifier_artifacts(output_dir, &verifier_data)?;

    // -------------------------------------------------------------------------
    // 4) Optionally build prover artifact
    // -------------------------------------------------------------------------
    if cfg.include_prover {
        let prover_data = layer1_circuit.build_prover();
        write_prover_artifact(output_dir, &prover_data)?;
    }

    // -------------------------------------------------------------------------
    // 5) Generate and write layer-1 dummy proof template (a dummy layer-0 proof)
    // -------------------------------------------------------------------------
    //
    // Layer-1 pads with *layer-0 aggregated proofs*, so the dummy template is produced
    // by running the layer-0 prover with an empty batch (it self-pads with leaf dummies).
    let layer0_dummy_proof = Layer0AggregationProver::new_from_binaries_dir(output_dir)
        .context("Failed to load layer-0 prover while generating layer1 dummy proof")?
        .commit(Layer0AggregationInputs { proofs: vec![] })
        .context("Failed to commit empty batch to layer-0 prover (for layer1 dummy proof)")?
        .prove()
        .context("Failed to generate layer1 dummy proof (dummy layer-0 proof)")?;

    write(
        output_dir.join("layer1_dummy_proof.bin"),
        layer0_dummy_proof.to_bytes(),
    )
    .with_context(|| {
        format!(
            "Failed to write {}",
            output_dir.join("layer1_dummy_proof.bin").display()
        )
    })?;

    println!(
        "Layer-1 circuit artifacts written to {} (num_layer0_proofs={}, layer0_num_leaves={})",
        output_dir.display(),
        cfg.num_layer0_proofs,
        cfg.layer0_num_leaves
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn load_layer0_common_from_bins(bins_dir: &Path) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;

    let bytes = std::fs::read(bins_dir.join("aggregated_common.bin")).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join("aggregated_common.bin").display()
        )
    })?;

    CommonCircuitData::from_bytes(bytes, &gate_serializer)
        .map_err(|e| anyhow!("Failed to deserialize aggregated_common.bin: {}", e))
}

fn write_verifier_artifacts(
    bins_dir: &Path,
    verifier_data: &VerifierCircuitData<F, C, D>,
) -> Result<()> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = verifier_data
        .common
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize layer1 common data: {}", e))?;

    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize layer1 verifier data: {}", e))?;

    write(bins_dir.join("layer1_common.bin"), common_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            bins_dir.join("layer1_common.bin").display()
        )
    })?;
    write(bins_dir.join("layer1_verifier.bin"), verifier_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            bins_dir.join("layer1_verifier.bin").display()
        )
    })?;

    Ok(())
}

fn write_prover_artifact(bins_dir: &Path, prover_data: &ProverCircuitData<F, C, D>) -> Result<()> {
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let prover_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, &prover_data.common)
        .map_err(|e| anyhow!("Failed to serialize layer1 prover data: {}", e))?;

    write(bins_dir.join("layer1_prover.bin"), prover_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            bins_dir.join("layer1_prover.bin").display()
        )
    })?;

    Ok(())
}
