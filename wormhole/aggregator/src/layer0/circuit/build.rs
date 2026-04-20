//! Prebuild / serialization helpers for the shipping compact-child 2x8 layer-0 stack.

use anyhow::{anyhow, Context, Result};
use plonky2::{
    plonk::circuit_data::CommonCircuitData,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use std::{
    fs::{copy, create_dir_all, write},
    path::Path,
};
use zk_circuits_common::circuit::{C, D, F};

use super::{
    constants::{
        INNER_COMMON_FILENAME, INNER_PROVER_FILENAME, INNER_TARGETS_FILENAME,
        INNER_VERIFIER_FILENAME, OUTER_COMMON_FILENAME, OUTER_PROVER_FILENAME,
        OUTER_TARGETS_FILENAME, OUTER_VERIFIER_FILENAME,
    },
    inner::InnerAggregationCircuit,
    outer::OuterAggregationCircuit,
};

pub fn generate_layer0_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    _num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    generate_inner_circuit_binaries(output_path, include_prover)?;
    generate_outer_circuit_binaries(output_path, include_prover)?;
    alias_outer_wrapper_as_aggregated(output_path, include_prover)?;

    Ok(())
}

fn generate_inner_circuit_binaries(output_dir: &Path, include_prover: bool) -> Result<()> {
    println!(
        "Building shipping 2x8 inner aggregation circuit (num_leaf_proofs=8, stable incremental unique-table)..."
    );

    let leaf_common = load_common_data(&output_dir.join("common.bin"), "leaf")?;
    let inner_circuit = InnerAggregationCircuit::new(leaf_common);
    let targets = inner_circuit.targets();
    let circuit_data = inner_circuit.build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize inner common data: {}", e))?;
    write(output_dir.join(INNER_COMMON_FILENAME), common_bytes)?;

    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize inner verifier data: {}", e))?;
    write(output_dir.join(INNER_VERIFIER_FILENAME), verifier_bytes)?;

    let targets_bytes = targets
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize inner targets: {}", e))?;
    write(output_dir.join(INNER_TARGETS_FILENAME), targets_bytes)?;

    if include_prover {
        let prover_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize inner prover data: {}", e))?;
        write(output_dir.join(INNER_PROVER_FILENAME), prover_bytes)?;
    }

    Ok(())
}

fn generate_outer_circuit_binaries(output_dir: &Path, include_prover: bool) -> Result<()> {
    println!("Building shipping 2x8 final public ZK wrapper circuit...");

    let inner_common = load_common_data(&output_dir.join(INNER_COMMON_FILENAME), "inner")?;
    let outer_circuit = OuterAggregationCircuit::new(inner_common);
    let targets = outer_circuit.targets();
    let circuit_data = outer_circuit.build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize outer common data: {}", e))?;
    write(output_dir.join(OUTER_COMMON_FILENAME), common_bytes)?;

    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize outer verifier data: {}", e))?;
    write(output_dir.join(OUTER_VERIFIER_FILENAME), verifier_bytes)?;

    let targets_bytes = targets
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize outer targets: {}", e))?;
    write(output_dir.join(OUTER_TARGETS_FILENAME), targets_bytes)?;

    if include_prover {
        let prover_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize outer prover data: {}", e))?;
        write(output_dir.join(OUTER_PROVER_FILENAME), prover_bytes)?;
    }

    Ok(())
}

fn alias_outer_wrapper_as_aggregated(output_dir: &Path, include_prover: bool) -> Result<()> {
    alias_file(output_dir, OUTER_COMMON_FILENAME, "aggregated_common.bin")?;
    alias_file(
        output_dir,
        OUTER_VERIFIER_FILENAME,
        "aggregated_verifier.bin",
    )?;
    alias_file(output_dir, OUTER_TARGETS_FILENAME, "aggregated_targets.bin")?;

    if include_prover {
        alias_file(output_dir, OUTER_PROVER_FILENAME, "aggregated_prover.bin")?;
    }

    Ok(())
}

fn alias_file(output_dir: &Path, src_name: &str, dst_name: &str) -> Result<()> {
    let src = output_dir.join(src_name);
    let dst = output_dir.join(dst_name);

    copy(&src, &dst)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))?;

    Ok(())
}

fn load_common_data(common_path: &Path, label: &str) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;
    let common_bytes = std::fs::read(common_path).with_context(|| {
        format!(
            "Failed to read {} common circuit file {:?}",
            label, common_path
        )
    })?;

    CommonCircuitData::from_bytes(common_bytes, &gate_serializer).map_err(|e| {
        anyhow!(
            "Failed to deserialize {} common circuit data from {:?}: {}",
            label,
            common_path,
            e
        )
    })
}
