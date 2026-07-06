//! Build + serialize layer-1 aggregation circuit artifacts.
//!
//! Generates: `layer1_common.bin`, `layer1_verifier.bin`, `layer1_prover.bin` (optional)
//!
//! Expects layer-0 artifacts to already exist in `output_dir`.

use anyhow::{anyhow, Context, Result};
use std::fs::{create_dir_all, write};
use std::path::Path;

use plonky2::plonk::circuit_data::{
    CommonCircuitData, ProverCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};

use zk_circuits_common::circuit::{wormhole_layer1_circuit_config, C, D, F};

use crate::common::utils::l0_num_leaves_from_padded_pi_len;
use crate::layer1::circuit::circuit_logic::Layer1AggregationCircuit;

/// Build and write all layer-1 artifacts into `output_dir`.
pub fn generate_layer1_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_layer0_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_dir = output_dir.as_ref();
    create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    let layer0_common = load_layer0_common_from_bins(output_dir)
        .context("Failed to load layer-0 common circuit data")?;
    let layer0_verifier_only = load_layer0_verifier_only_from_bins(output_dir)
        .context("Failed to load layer-0 verifier data")?;

    let layer0_num_leaves = l0_num_leaves_from_padded_pi_len(layer0_common.num_public_inputs)?;

    // Non-ZK config: layer-1 witnesses (layer-0 proofs) are already public data and their
    // public inputs are forwarded verbatim, so blinding buys nothing and slows proving.
    let layer1_circuit = Layer1AggregationCircuit::new(
        wormhole_layer1_circuit_config(),
        layer0_common,
        &layer0_verifier_only,
        num_layer0_proofs,
        layer0_num_leaves,
    );

    let circuit_data = layer1_circuit.build_circuit();
    let verifier_data = circuit_data.verifier_data();
    write_verifier_artifacts(output_dir, &verifier_data)?;

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

fn load_layer0_verifier_only_from_bins(bins_dir: &Path) -> Result<VerifierOnlyCircuitData<C, D>> {
    let bytes = std::fs::read(bins_dir.join("aggregated_verifier.bin")).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join("aggregated_verifier.bin").display()
        )
    })?;

    VerifierOnlyCircuitData::from_bytes(bytes)
        .map_err(|e| anyhow!("Failed to deserialize aggregated_verifier.bin: {}", e))
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
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
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
