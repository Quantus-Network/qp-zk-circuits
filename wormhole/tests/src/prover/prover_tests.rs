use std::fs;

use hex;
use plonky2::plonk::circuit_data::CircuitConfig;
use test_helpers::storage_proof::TestInputs;
use wormhole_circuit::inputs::{CircuitInputs, PublicCircuitInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::BytesDigest;

#[cfg(test)]
const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

#[test]
fn commit_and_prove() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    prover.commit(&inputs).unwrap().prove().unwrap();
}

#[test]
fn proof_can_be_deserialized() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let public_inputs = PublicCircuitInputs::try_from(&proof).unwrap();

    // Build the expected values
    let expected = PublicCircuitInputs {
        funding_amount: 1_000_000_000_000u128,
        nullifier: BytesDigest::try_from([
            169, 76, 150, 35, 66, 248, 76, 193, 57, 204, 106, 33, 169, 160, 248, 113, 235, 144,
            212, 48, 9, 232, 146, 7, 105, 125, 170, 24, 33, 54, 135, 28,
        ])
        .unwrap(),
        root_hash: BytesDigest::try_from([
            95, 250, 42, 181, 176, 219, 152, 131, 178, 43, 30, 88, 16, 147, 46, 169, 217, 234, 177,
            132, 7, 48, 253, 57, 172, 231, 28, 38, 187, 141, 8, 45,
        ])
        .unwrap(),
        exit_account: BytesDigest::try_from([4u8; 32]).unwrap(),
    };
    assert_eq!(public_inputs, expected);
    println!("{:?}", public_inputs);
}

#[test]
fn get_public_inputs() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let public_inputs = proof.public_inputs;
    println!("{:?}", public_inputs);
}

#[test]
#[ignore = "debug"]
fn export_test_proof() {
    const FILE_PATH: &str = "../../dummy_proof.bin";

    let circuit_config = CircuitConfig::standard_recursion_config();

    let prover = WormholeProver::new(circuit_config);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let _ = fs::write(FILE_PATH, proof_bytes);
}

#[test]
#[ignore = "debug"]
fn export_test_proof_zk() {
    const FILE_PATH: &str = "../../dummy_proof_zk.bin";

    let circuit_config = CircuitConfig::standard_recursion_zk_config();

    let prover = WormholeProver::new(circuit_config);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let _ = fs::write(FILE_PATH, proof_bytes);
}

#[test]
#[ignore = "debug"]
fn export_hex_proof_for_pallet() {
    const FILE_PATH: &str = "proof.hex";

    let circuit_config = CircuitConfig::standard_recursion_config();

    let prover = WormholeProver::new(circuit_config);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let hex_proof = hex::encode(proof_bytes);
    let _ = fs::write(FILE_PATH, hex_proof);
}

#[test]
#[ignore = "debug"]
fn export_hex_proof_from_bins_for_pallet() {
    const FILE_PATH: &str = "proof_from_bins.hex";

    // Use the pre-generated bin files to ensure compatibility with the verifier
    let prover = WormholeProver::new_from_files(
        std::path::Path::new("../../generated-bins/prover.bin"),
        std::path::Path::new("../../generated-bins/common.bin"),
    )
    .expect("Failed to load prover from bin files");

    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let proof_size = proof_bytes.len();
    let hex_proof = hex::encode(proof_bytes);
    let _ = fs::write(FILE_PATH, hex_proof);

    println!("Generated proof hex file: {}", FILE_PATH);
    println!("Proof size: {} bytes", proof_size);
}
