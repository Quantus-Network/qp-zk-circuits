use anyhow::{anyhow, Result};
use std::fs::{create_dir_all, write};
use std::path::Path;

use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use wormhole_aggregator::WormholeProofAggregator;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::D;

/// Generate wormhole circuit binaries (verifier.bin, common.bin, and optionally prover.bin)
pub fn generate_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
) -> Result<()> {
    println!("Building wormhole circuit...");
    let config = CircuitConfig::standard_recursion_zk_config();
    let circuit = WormholeCircuit::new(config);
    let circuit_data = circuit.build_circuit();
    println!("Circuit built.");

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    println!("Serializing circuit data...");

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    // Serialize common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize common data: {}", e))?;
    write(output_path.join("common.bin"), common_bytes)?;
    println!("Common data saved to {}/common.bin", output_path.display());

    // Serialize verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize verifier data: {}", e))?;
    write(output_path.join("verifier.bin"), verifier_only_bytes)?;
    println!(
        "Verifier data saved to {}/verifier.bin",
        output_path.display()
    );

    // Serialize prover only data (optional)
    if include_prover {
        let prover_only_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize prover data: {}", e))?;
        write(output_path.join("prover.bin"), prover_only_bytes)?;
        println!("Prover data saved to {}/prover.bin", output_path.display());
    } else {
        println!("Skipping prover binary generation");
    }

    Ok(())
}

/// Generate aggregated circuit binaries (aggregated_verifier.bin, aggregated_common.bin)
///
/// The aggregated circuit is built by running the aggregation process on dummy proofs.
/// This requires creating a full aggregation tree which is computationally expensive.
///
/// IMPORTANT: This must be called AFTER generate_circuit_binaries() so that the
/// leaf circuit files (prover.bin, common.bin, verifier.bin) already exist.
/// The aggregator loads from these files to ensure consistency.
pub fn generate_aggregated_circuit_binaries<P: AsRef<Path>>(output_dir: P) -> Result<()> {
    println!("Building aggregated wormhole circuit...");

    // IMPORTANT: Use from_prebuilt() to load the leaf circuit from the files
    // we just generated. This ensures the aggregated circuit's leaf verifier data
    // matches the leaf circuit files exactly.
    //
    // If we used from_circuit_config(), it would build a fresh leaf circuit which
    // might differ from the one in common.bin/verifier.bin, causing verification
    // failures when the chain tries to verify aggregated proofs.
    let mut aggregator = WormholeProofAggregator::from_prebuilt()
        .map_err(|e| anyhow!("Failed to create aggregator from pre-built files. Make sure generate_circuit_binaries() was called first: {}", e))?;

    // We need to run the aggregation to get the circuit data.
    // The aggregator builds the circuit dynamically during aggregation.
    // To get the circuit data without real proofs, we use dummy proofs.
    println!("Running aggregation with dummy proofs to build circuit...");
    let aggregated_proof = aggregator.aggregate()?;
    println!("Aggregated circuit built.");

    let gate_serializer = DefaultGateSerializer;

    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    // Serialize aggregated common data
    let agg_common_bytes = aggregated_proof
        .circuit_data
        .common
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize aggregated common data: {}", e))?;
    write(output_path.join("aggregated_common.bin"), agg_common_bytes)?;
    println!(
        "Aggregated common data saved to {}/aggregated_common.bin",
        output_path.display()
    );

    // Serialize aggregated verifier only data
    let agg_verifier_only_bytes = aggregated_proof
        .circuit_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;
    write(
        output_path.join("aggregated_verifier.bin"),
        agg_verifier_only_bytes,
    )?;
    println!(
        "Aggregated verifier data saved to {}/aggregated_verifier.bin",
        output_path.display()
    );

    Ok(())
}

/// Generate all circuit binaries (both regular and aggregated)
pub fn generate_all_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();

    // Generate regular circuit binaries
    generate_circuit_binaries(output_path, include_prover)?;

    // Generate aggregated circuit binaries
    generate_aggregated_circuit_binaries(output_path)?;

    Ok(())
}

pub fn main() -> Result<()> {
    generate_circuit_binaries("generated-bins", true)
}
