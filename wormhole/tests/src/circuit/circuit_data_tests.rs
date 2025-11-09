use anyhow::Result;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use std::fs;
use std::path::Path;
use test_helpers::TestInputs;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::circuit::{circuit_data_from_bytes, circuit_data_to_bytes};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::circuit::D;

#[test]
fn test_circuit_data_serialization() {
    // Build the circuit from source
    let config = CircuitConfig::standard_recursion_config();
    let circuit = WormholeCircuit::new(config);
    let built_circuit_data = circuit.build_circuit();

    // Serialize the circuit data to bytes
    let serialized_bytes =
        circuit_data_to_bytes(&built_circuit_data).expect("Failed to serialize circuit data");

    // Deserialize the bytes back to circuit data
    let deserialized_circuit_data =
        circuit_data_from_bytes(&serialized_bytes).expect("Failed to deserialize circuit data");

    // Re-serialize the deserialized circuit data
    let reserialized_bytes = circuit_data_to_bytes(&deserialized_circuit_data)
        .expect("Failed to re-serialize circuit data");

    // Assert that the original and re-serialized bytes are identical
    assert_eq!(serialized_bytes, reserialized_bytes);
}

#[test]
fn test_prover_and_verifier_from_file_e2e() -> Result<()> {
    // Create a temp directory for the test files
    let temp_dir = "temp_test_bins_e2e";
    fs::create_dir_all(temp_dir)?;

    // Generate circuit and write component files to the temporary directory.
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // Serialize and write common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let common_path = Path::new(temp_dir).join("common.bin");
    fs::write(&common_path, &common_bytes)?;

    // Serialize and write verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let verifier_path = Path::new(temp_dir).join("verifier.bin");
    fs::write(&verifier_path, &verifier_only_bytes)?;

    // Serialize and write prover only data
    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let prover_path = Path::new(temp_dir).join("prover.bin");
    fs::write(&prover_path, &prover_only_bytes)?;

    // Create a prover and verifier from the temporary files.
    let prover = WormholeProver::new_from_files(&prover_path, &common_path)?;
    let verifier = WormholeVerifier::new_from_files(&verifier_path, &common_path)?;

    // Create inputs
    let inputs = CircuitInputs::test_inputs_0();

    // Generate and verify a proof
    let prover_next = prover.commit(&inputs)?;
    let proof = prover_next.prove()?;
    verifier.verify(proof)?;

    // Clean up the temporary directory
    fs::remove_dir_all(temp_dir)?;

    Ok(())
}
