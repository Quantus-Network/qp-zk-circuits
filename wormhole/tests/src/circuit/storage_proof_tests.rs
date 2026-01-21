use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use std::panic;
use wormhole_circuit::{
    storage_proof::{leaf::LeafInputs, ProcessedStorageProof, StorageProof, StorageProofTargets},
    substrate_account::SubstrateAccount,
};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    utils::u64_to_felts,
};

use test_helpers::storage_proof::default_root_hash;
use test_helpers::TestInputs;

#[cfg(test)]
fn run_test(storage_proof: &StorageProof) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = StorageProofTargets::new(&mut builder);
    StorageProof::circuit(&targets, &mut builder);

    storage_proof.fill_targets(&mut pw, targets).unwrap();
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_proof() {
    let storage_proof = StorageProof::test_inputs_0();
    run_test(&storage_proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_root_hash_fails() {
    let mut proof = StorageProof::test_inputs_0();
    proof.root_hash = [0u8; 32];
    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn tampered_proof_fails() {
    let mut tampered_proof = ProcessedStorageProof::test_inputs_0();

    // Flip the first byte in the first node hash. Divide by two to get the byte index.
    let hash_index = tampered_proof.indices[0] / 2;
    tampered_proof.proof[0][hash_index] ^= 0xFF;
    let proof = StorageProof::new(
        &tampered_proof,
        default_root_hash(),
        LeafInputs::test_inputs_0(),
    );

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_nonce() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the nonce.
    leaf_inputs.transfer_count = u64_to_felts(5);

    let proof = StorageProof::new(&proof, default_root_hash(), leaf_inputs);

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_exit_address() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the to account.
    leaf_inputs.to_account = SubstrateAccount::new(&[0; 32]).unwrap();

    let proof = StorageProof::new(&proof, default_root_hash(), leaf_inputs);

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_input_amount() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the input amount (which is used for the leaf hash in storage).
    leaf_inputs.input_amount = F::from_canonical_u64(1000);

    let proof = StorageProof::new(&proof, default_root_hash(), leaf_inputs);

    run_test(&proof).unwrap();
}

#[ignore = "performance"]
#[test]
fn fuzz_tampered_proof() {
    const FUZZ_ITERATIONS: usize = 1000;

    // Number of fuzzing iterations
    let mut panic_count = 0;

    for i in 0..FUZZ_ITERATIONS {
        // Clone the original storage proof
        let mut tampered_proof = ProcessedStorageProof::test_inputs_0();

        // Randomly select a node in the proof to tamper
        let node_index = rand::random_range(0..tampered_proof.proof.len());

        // Randomly select a byte to flip
        let byte_index = rand::random_range(0..tampered_proof.proof[node_index].len());

        // Flip random bits in the selected byte (e.g., XOR with a random value)
        tampered_proof.proof[node_index][byte_index] ^= rand::random_range(1..=255);

        // Create the proof and inputs
        let proof = StorageProof::new(
            &tampered_proof,
            default_root_hash(),
            LeafInputs::test_inputs_0(),
        );

        // Catch panic from run_test
        let result = panic::catch_unwind(|| {
            run_test(&proof).unwrap();
        });

        if result.is_err() {
            panic_count += 1;
        } else {
            // Optionally log cases where tampering didn't cause a panic
            println!("Iteration {i}: No panic occurred for tampered proof");
        }
    }

    assert_eq!(
        panic_count, FUZZ_ITERATIONS,
        "Only {panic_count} out of {FUZZ_ITERATIONS} iterations panicked",
    );
}
