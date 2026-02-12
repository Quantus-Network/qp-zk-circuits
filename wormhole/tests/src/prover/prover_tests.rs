use std::fs;

use hex;
use plonky2::plonk::circuit_data::CircuitConfig;
use qp_wormhole_inputs::PublicCircuitInputs;
use test_helpers::{
    block_header::{DEFAULT_BLOCK_HASHES, DEFAULT_BLOCK_NUMBERS, DEFAULT_PARENT_HASHES},
    TestInputs, DEFAULT_OUTPUT_AMOUNTS, DEFAULT_VOLUME_FEE_BPS,
};
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
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

    let public_inputs = PublicCircuitInputs::try_from_proof(&proof).unwrap();

    // Build the expected values
    let expected = PublicCircuitInputs {
        asset_id: 0u32,
        output_amount_1: DEFAULT_OUTPUT_AMOUNTS[0],
        output_amount_2: 0u32, // No second output in tests
        volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
        nullifier: BytesDigest::try_from([
            102, 213, 23, 119, 137, 1, 172, 231, 97, 86, 27, 28, 210, 26, 24, 162, 195, 135, 231,
            170, 205, 111, 30, 63, 225, 212, 217, 138, 233, 170, 170, 122,
        ])
        .unwrap(),
        exit_account_1: BytesDigest::try_from([4u8; 32]).unwrap(),
        exit_account_2: BytesDigest::default(), // No second exit account
        block_hash: BytesDigest::try_from(DEFAULT_BLOCK_HASHES[0]).unwrap(),
        parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap(),
        block_number: DEFAULT_BLOCK_NUMBERS[0],
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
