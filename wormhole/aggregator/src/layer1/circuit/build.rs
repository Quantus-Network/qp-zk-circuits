//! Build + serialize layer-1 aggregation circuit artifacts.
//!
//! Produces:
//! - `layer1_common.bin`
//! - `layer1_verifier.bin`
//! - `layer1_prover.bin` (optional)
//! - `layer1_targets.json`
//!
//! Expects layer-0 artifacts to already exist in `output_dir`:
//! - `aggregated_common.bin`
//! - `aggregated_verifier.bin`
//! - `aggregated_prover.bin`
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

use crate::layer1::circuit::constants::l0_num_leaves_from_pi_len;
use crate::layer1::{
    circuit::circuit_logic::Layer1AggregationCircuit, prover::targets_layout::Layer1TargetsLayoutD,
};

/// Build and write all layer-1 artifacts into `output_dir`.
///
/// This assumes layer-0 artifacts are already present in `output_dir`.
pub fn generate_layer1_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_layer0_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_dir = output_dir.as_ref();
    create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    // -------------------------------------------------------------------------
    // 1) Load layer-0 common circuit data (child circuit for layer-1)
    // -------------------------------------------------------------------------
    let layer0_common = load_layer0_common_from_bins(output_dir)
        .context("Failed to load layer-0 common circuit data from bins dir. Make sure the dependent layer-0 artifacts are present in the output directory")?;

    let layer0_num_leaves = l0_num_leaves_from_pi_len(layer0_common.num_public_inputs);
    // -------------------------------------------------------------------------
    // 2) Build layer-1 circuit + targets layout
    // -------------------------------------------------------------------------
    let layer1_circuit = Layer1AggregationCircuit::new(
        CircuitConfig::standard_recursion_zk_config(),
        layer0_common,
        num_layer0_proofs,
        layer0_num_leaves,
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
    let circuit_data = layer1_circuit.build_circuit();
    let verifier_data = circuit_data.verifier_data();
    write_verifier_artifacts(output_dir, &verifier_data)?;

    // -------------------------------------------------------------------------
    // 4) Optionally build prover artifact
    // -------------------------------------------------------------------------
    if include_prover {
        let prover_data = circuit_data.prover_data();
        write_prover_artifact(output_dir, &prover_data)?;
    }

    println!(
        "Layer-1 circuit artifacts written to {} (num_layer0_proofs={}, layer0_num_leaves={})",
        output_dir.display(),
        num_layer0_proofs,
        layer0_num_leaves
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
