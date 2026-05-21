//! Prebuild / serialization helpers for the compact-child Layer-0 aggregation circuit.
//!
//! Generates the production 2x8 topology:
//! - `inner_common.bin`, `inner_verifier.bin`, `inner_prover.bin`, `inner_targets.bin`
//! - `outer_common.bin`, `outer_verifier.bin`, `outer_prover.bin`, `outer_targets.bin`
//! - legacy `aggregated_*` aliases for the outer proof artifacts
//!
//! Expects `common.bin` and `verifier.bin` to already exist in the output directory.

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use std::{
    fs::{create_dir_all, write},
    path::Path,
};
use zk_circuits_common::circuit::{C, D, F};

use crate::layer0::circuit::{
    constants::{
        INNER_COMMON_FILENAME, INNER_PROVER_FILENAME, INNER_TARGETS_FILENAME,
        INNER_VERIFIER_FILENAME, OUTER_COMMON_FILENAME, OUTER_PROVER_FILENAME,
        OUTER_TARGETS_FILENAME, OUTER_VERIFIER_FILENAME, TOTAL_NUM_LEAVES,
    },
    inner::InnerAggregationCircuit,
    outer::OuterAggregationCircuit,
};

/// Generate prebuilt Layer-0 aggregation circuit binaries.
pub fn generate_layer0_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    if num_leaf_proofs != TOTAL_NUM_LEAVES {
        bail!(
            "production compact-child layer-0 capacity is fixed at {} leaves, got {}",
            TOTAL_NUM_LEAVES,
            num_leaf_proofs
        );
    }

    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    println!(
        "Building compact-child layer-0 aggregation circuits (num_leaf_proofs={})...",
        num_leaf_proofs
    );

    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
    let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let inner_circuit = InnerAggregationCircuit::new(leaf_common, &leaf_verifier_only);
    let inner_targets = inner_circuit.targets();
    let inner_circuit_data = inner_circuit.build_circuit();
    let inner_verifier_data = inner_circuit_data.verifier_data();
    let inner_prover_data = inner_circuit_data.prover_data();
    let inner_common_data = &inner_verifier_data.common;

    let inner_common_bytes = inner_common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize inner common data: {}", e))?;
    write(output_path.join(INNER_COMMON_FILENAME), &inner_common_bytes)?;
    println!("Saved {}/{}", output_path.display(), INNER_COMMON_FILENAME);

    let inner_verifier_only_bytes = inner_verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize inner verifier data: {}", e))?;
    write(
        output_path.join(INNER_VERIFIER_FILENAME),
        &inner_verifier_only_bytes,
    )?;
    println!(
        "Saved {}/{}",
        output_path.display(),
        INNER_VERIFIER_FILENAME
    );

    let inner_targets_bytes = inner_targets
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize inner targets: {}", e))?;
    write(
        output_path.join(INNER_TARGETS_FILENAME),
        inner_targets_bytes,
    )?;
    println!("Saved {}/{}", output_path.display(), INNER_TARGETS_FILENAME);

    if include_prover {
        let inner_prover_only_bytes = inner_prover_data
            .prover_only
            .to_bytes(&generator_serializer, inner_common_data)
            .map_err(|e| anyhow!("Failed to serialize inner prover data: {}", e))?;
        write(
            output_path.join(INNER_PROVER_FILENAME),
            &inner_prover_only_bytes,
        )?;
        println!("Saved {}/{}", output_path.display(), INNER_PROVER_FILENAME);
    } else {
        println!("Skipping inner prover binary generation");
    }

    let outer_circuit = OuterAggregationCircuit::new(
        inner_verifier_data.common.clone(),
        &inner_verifier_data.verifier_only,
    );
    let outer_targets = outer_circuit.targets();
    let outer_circuit_data = outer_circuit.build_circuit();
    let outer_verifier_data = outer_circuit_data.verifier_data();
    let outer_prover_data = outer_circuit_data.prover_data();
    let outer_common_data = &outer_verifier_data.common;

    let outer_common_bytes = outer_common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize outer common data: {}", e))?;
    write(output_path.join(OUTER_COMMON_FILENAME), &outer_common_bytes)?;
    write(
        output_path.join("aggregated_common.bin"),
        &outer_common_bytes,
    )?;
    println!("Saved {}/{}", output_path.display(), OUTER_COMMON_FILENAME);
    println!("Saved {}/aggregated_common.bin", output_path.display());

    let outer_verifier_only_bytes = outer_verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize outer verifier data: {}", e))?;
    write(
        output_path.join(OUTER_VERIFIER_FILENAME),
        &outer_verifier_only_bytes,
    )?;
    write(
        output_path.join("aggregated_verifier.bin"),
        &outer_verifier_only_bytes,
    )?;
    println!(
        "Saved {}/{}",
        output_path.display(),
        OUTER_VERIFIER_FILENAME
    );
    println!("Saved {}/aggregated_verifier.bin", output_path.display());

    let outer_targets_bytes = outer_targets
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize outer targets: {}", e))?;
    write(
        output_path.join(OUTER_TARGETS_FILENAME),
        &outer_targets_bytes,
    )?;
    write(
        output_path.join("aggregated_targets.bin"),
        &outer_targets_bytes,
    )?;
    println!("Saved {}/{}", output_path.display(), OUTER_TARGETS_FILENAME);
    println!("Saved {}/aggregated_targets.bin", output_path.display());

    if include_prover {
        let outer_prover_only_bytes = outer_prover_data
            .prover_only
            .to_bytes(&generator_serializer, outer_common_data)
            .map_err(|e| anyhow!("Failed to serialize outer prover data: {}", e))?;
        write(
            output_path.join(OUTER_PROVER_FILENAME),
            &outer_prover_only_bytes,
        )?;
        write(
            output_path.join("aggregated_prover.bin"),
            &outer_prover_only_bytes,
        )?;
        println!("Saved {}/{}", output_path.display(), OUTER_PROVER_FILENAME);
        println!("Saved {}/aggregated_prover.bin", output_path.display());
    } else {
        println!("Skipping outer prover binary generation");
    }

    Ok(())
}

fn load_leaf_common_data(common_path: &Path) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = std::fs::read(common_path)
        .with_context(|| format!("Failed to read leaf common circuit file {:?}", common_path))?;

    CommonCircuitData::from_bytes(common_bytes, &gate_serializer).map_err(|e| {
        anyhow!(
            "Failed to deserialize leaf common circuit data from {:?}: {}",
            common_path,
            e
        )
    })
}

fn load_leaf_verifier_only_data(verifier_path: &Path) -> Result<VerifierOnlyCircuitData<C, D>> {
    let verifier_bytes = std::fs::read(verifier_path).with_context(|| {
        format!(
            "Failed to read leaf verifier circuit file {:?}",
            verifier_path
        )
    })?;

    VerifierOnlyCircuitData::from_bytes(verifier_bytes).map_err(|e| {
        anyhow!(
            "Failed to deserialize leaf verifier circuit data from {:?}: {}",
            verifier_path,
            e
        )
    })
}
