//! Prebuild / serialization helpers for the monolithic Layer-0 aggregation circuit.
//!
//! This generates the prebuilt circuit artifacts used by `Layer0AggregationProver` and verifier.
//!
//! With the ZK wrapper optimization enabled (default), generates:
//! - `aggregated_nonzk_common.bin` - non-ZK L0 circuit common data
//! - `aggregated_nonzk_verifier.bin` - non-ZK L0 circuit verifier
//! - `aggregated_nonzk_prover.bin` - non-ZK L0 circuit prover
//! - `wrapper_common.bin` - ZK wrapper circuit common data  
//! - `wrapper_verifier.bin` - ZK wrapper circuit verifier
//! - `wrapper_prover.bin` - ZK wrapper circuit prover
//! - `aggregated_common.bin` - symlink/copy to wrapper_common.bin (for compatibility)
//! - `aggregated_verifier.bin` - symlink/copy to wrapper_verifier.bin (for compatibility)
//!
//! The old direct ZK approach can still be used by calling `generate_layer0_circuit_binaries_zk`.
//!
//! Expects `common.bin` and `verifier.bin` to already exist in the output directory.

use anyhow::{anyhow, Context, Result};
use plonky2::{
    plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use std::{
    fs::{create_dir_all, write},
    path::Path,
};
use zk_circuits_common::circuit::{wormhole_aggregator_circuit_config, C, D, F};

use crate::layer0::circuit::circuit_logic::Layer0AggregationCircuit;
use crate::zk_wrapper::build::generate_wrapper_circuit_binaries;

/// Generate prebuilt Layer-0 aggregation circuit binaries using the ZK wrapper optimization.
///
/// This is the recommended approach, providing ~1.8x speedup over direct ZK aggregation.
///
/// # Process
/// 1. Build non-ZK L0 circuit → `aggregated_nonzk_*.bin`
/// 2. Build ZK wrapper → `wrapper_*.bin`
/// 3. Create compatibility aliases → `aggregated_common.bin`, `aggregated_verifier.bin`
///
/// # Expected inputs (already generated in `output_dir`)
/// - `common.bin` (leaf common circuit data)
/// - `verifier.bin` (leaf verifier-only circuit data)
///
/// # Outputs (written to `output_dir`)
/// - `aggregated_nonzk_common.bin`, `aggregated_nonzk_verifier.bin`, `aggregated_nonzk_prover.bin`
/// - `wrapper_common.bin`, `wrapper_verifier.bin`, `wrapper_prover.bin`
/// - `aggregated_common.bin` (copy of wrapper_common.bin)
/// - `aggregated_verifier.bin` (copy of wrapper_verifier.bin)
pub fn generate_layer0_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    // Step 1: Build non-ZK L0 circuit
    println!(
        "Building non-ZK layer-0 aggregation circuit (num_leaf_proofs={})...",
        num_leaf_proofs
    );
    generate_layer0_nonzk_binaries(output_path, num_leaf_proofs, include_prover)?;

    // Step 2: Build ZK wrapper circuit
    println!("Building ZK wrapper circuit...");
    generate_wrapper_circuit_binaries(output_path, include_prover)?;

    // Step 3: Create compatibility aliases (copy wrapper binaries to aggregated_* names)
    // This ensures backward compatibility with code expecting aggregated_common.bin etc.
    println!("Creating compatibility aliases...");

    std::fs::copy(
        output_path.join("wrapper_common.bin"),
        output_path.join("aggregated_common.bin"),
    )
    .context("Failed to copy wrapper_common.bin to aggregated_common.bin")?;
    println!(
        "Saved {}/aggregated_common.bin (from wrapper)",
        output_path.display()
    );

    std::fs::copy(
        output_path.join("wrapper_verifier.bin"),
        output_path.join("aggregated_verifier.bin"),
    )
    .context("Failed to copy wrapper_verifier.bin to aggregated_verifier.bin")?;
    println!(
        "Saved {}/aggregated_verifier.bin (from wrapper)",
        output_path.display()
    );

    if include_prover {
        std::fs::copy(
            output_path.join("wrapper_prover.bin"),
            output_path.join("aggregated_prover.bin"),
        )
        .context("Failed to copy wrapper_prover.bin to aggregated_prover.bin")?;
        println!(
            "Saved {}/aggregated_prover.bin (from wrapper)",
            output_path.display()
        );
    }

    Ok(())
}

/// Generate only the non-ZK L0 circuit binaries.
///
/// # Outputs
/// - `aggregated_nonzk_common.bin`
/// - `aggregated_nonzk_verifier.bin`
/// - `aggregated_nonzk_prover.bin` (if include_prover is true)
fn generate_layer0_nonzk_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();

    // Load leaf common and verifier data
    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
    let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;

    // Build non-ZK L0 aggregation circuit
    let nonzk_config = CircuitConfig::standard_recursion_config(); // non-ZK
    let agg_circuit = Layer0AggregationCircuit::new(
        nonzk_config,
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

    // Serialize aggregated_nonzk_common.bin
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize non-ZK common data: {}", e))?;
    write(
        output_path.join("aggregated_nonzk_common.bin"),
        common_bytes,
    )?;
    println!(
        "Saved {}/aggregated_nonzk_common.bin",
        output_path.display()
    );

    // Serialize aggregated_nonzk_verifier.bin
    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize non-ZK verifier data: {}", e))?;
    write(
        output_path.join("aggregated_nonzk_verifier.bin"),
        verifier_bytes,
    )?;
    println!(
        "Saved {}/aggregated_nonzk_verifier.bin",
        output_path.display()
    );

    // Serialize aggregated_nonzk_prover.bin
    if include_prover {
        let prover_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize non-ZK prover data: {}", e))?;
        write(
            output_path.join("aggregated_nonzk_prover.bin"),
            prover_bytes,
        )?;
        println!(
            "Saved {}/aggregated_nonzk_prover.bin",
            output_path.display()
        );
    }

    Ok(())
}

/// Generate prebuilt Layer-0 aggregation circuit binaries using direct ZK (legacy approach).
///
/// Use this for backward compatibility or when the wrapper overhead is not acceptable.
/// Note: This is ~1.8x slower than the wrapper approach.
///
/// # Outputs
/// - `aggregated_common.bin`
/// - `aggregated_verifier.bin`
/// - `aggregated_prover.bin`
pub fn generate_layer0_circuit_binaries_zk<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    println!(
        "Building prebuilt layer-0 aggregation circuit (ZK, num_leaf_proofs={})...",
        num_leaf_proofs
    );

    // Load leaf common and verifier data
    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
    let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;

    // Build ZK L0 aggregation circuit (the old approach)
    let agg_circuit = Layer0AggregationCircuit::new(
        wormhole_aggregator_circuit_config(), // ZK config
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
    write(output_path.join("aggregated_common.bin"), agg_common_bytes)?;
    println!("Saved {}/aggregated_common.bin", output_path.display());

    let agg_verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;
    write(
        output_path.join("aggregated_verifier.bin"),
        agg_verifier_only_bytes,
    )?;
    println!("Saved {}/aggregated_verifier.bin", output_path.display());

    if include_prover {
        let agg_prover_only_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize aggregated prover data: {}", e))?;
        write(
            output_path.join("aggregated_prover.bin"),
            agg_prover_only_bytes,
        )?;
        println!("Saved {}/aggregated_prover.bin", output_path.display());
    } else {
        println!("Skipping aggregated prover binary generation");
    }
    Ok(())
}

/// Load leaf `common.bin` from disk.
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
