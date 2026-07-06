//! Prebuild / serialization helpers for the monolithic Private-batch aggregation circuit.
//!
//! Generates: `private_batch_common.bin`, `private_batch_verifier.bin`, `private_batch_prover.bin`
//!
//! Expects `common.bin` and `verifier.bin` to already exist in the output directory.

use anyhow::{anyhow, Context, Result};
use plonky2::{
    plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use std::{
    fs::{create_dir_all, write},
    path::Path,
};
use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};

use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;

/// Generate prebuilt Private-batch aggregation circuit binaries.
pub fn generate_private_batch_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    println!(
        "Building prebuilt private-batch aggregation circuit (num_leaf_proofs={})...",
        num_leaf_proofs
    );

    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
    let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;

    let agg_circuit = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        leaf_common,
        &leaf_verifier_only,
        num_leaf_proofs,
    );

    let circuit_data = agg_circuit.build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    let agg_common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize aggregated common data: {}", e))?;
    write(output_path.join("private_batch_common.bin"), agg_common_bytes)?;
    println!("Saved {}/private_batch_common.bin", output_path.display());

    let agg_verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;
    write(
        output_path.join("private_batch_verifier.bin"),
        agg_verifier_only_bytes,
    )?;
    println!("Saved {}/private_batch_verifier.bin", output_path.display());

    if include_prover {
        let agg_prover_only_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize aggregated prover data: {}", e))?;
        write(
            output_path.join("private_batch_prover.bin"),
            agg_prover_only_bytes,
        )?;
        println!("Saved {}/private_batch_prover.bin", output_path.display());
    } else {
        println!("Skipping aggregated prover binary generation");
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
