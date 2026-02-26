use anyhow::{anyhow, Result};
use std::fs::{create_dir_all, write};
use std::path::Path;

use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use wormhole_aggregator::layer0::circuit::build::generate_layer0_circuit_binaries;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::D;

// Re-export CircuitBinsConfig from aggregator so users of circuit-builder can access it
pub use wormhole_aggregator::CircuitBinsConfig;

/// Generate wormhole circuit binaries (verifier.bin, common.bin, dummy_proof.bin, and optionally prover.bin)
pub fn generate_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
) -> Result<()> {
    println!("Building wormhole circuit...");
    let config = CircuitConfig::standard_recursion_zk_config();
    let circuit = WormholeCircuit::new(config);
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();
    println!("Circuit built.");

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    // Generate dummy proof BEFORE consuming circuit_data (prove() borrows, prover_data() moves)
    println!("Generating dummy proof for aggregation padding...");
    let dummy_proof_bytes = wormhole_aggregator::generate_dummy_proof(&circuit_data, &targets)
        .map_err(|e| anyhow!("Failed to generate dummy proof: {}", e))?;
    write(output_path.join("dummy_proof.bin"), &dummy_proof_bytes)?;
    println!(
        "Dummy proof saved to {}/dummy_proof.bin ({} bytes)",
        output_path.display(),
        dummy_proof_bytes.len()
    );

    println!("Serializing circuit data...");

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

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

/// Generate all circuit binaries (both regular and aggregated)
///
/// # Arguments
/// * `output_dir` - Directory to write the binaries to
/// * `include_prover` - Whether to include the prover binary
/// * `num_leaf_proofs` - Number of leaf proofs aggregated into a single proof
/// * `num_innner_proofs` - Optional param for number of inner proofs (for layer-1 circuit). Set to none if you only want layer-0 aggregation.
// TODO: add `num_inner_proofs` argument once we support inner proof aggregation in layer-1 circuit
pub fn generate_all_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
    num_leaf_proofs: usize,
) -> Result<()> {
    let output_path = output_dir.as_ref();

    // Generate regular circuit binaries
    generate_circuit_binaries(output_path, include_prover)?;

    // Generate aggregated circuit binaries
    generate_layer0_circuit_binaries(output_path, num_leaf_proofs, include_prover)?;

    // Save config file alongside binaries (with hashes for integrity verification)
    let config = CircuitBinsConfig::new(num_leaf_proofs).with_hashes_from_directory(output_path)?;
    config.save(output_path)?;

    // Print hashes for reference
    if let Some(ref hashes) = config.hashes {
        println!("Binary hashes:");
        if let Some(ref h) = hashes.common {
            println!("  common.bin: {}", h);
        }
        if let Some(ref h) = hashes.verifier {
            println!("  verifier.bin: {}", h);
        }
        if let Some(ref h) = hashes.prover {
            println!("  prover.bin: {}", h);
        }
        if let Some(ref h) = hashes.aggregated_common {
            println!("  aggregated_common.bin: {}", h);
        }
        if let Some(ref h) = hashes.aggregated_verifier {
            println!("  aggregated_verifier.bin: {}", h);
        }
    }

    Ok(())
}
