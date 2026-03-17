use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use std::panic;
use wormhole_circuit::{
    storage_proof::{
        leaf::LeafInputs, ProcessedStorageProof, StorageProof, StorageProofTargets, MAX_PROOF_LEN,
        PROOF_NODE_MAX_SIZE_F,
    },
    substrate_account::SubstrateAccount,
};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    storage_proof::hash_node_with_poseidon_padded,
    utils::{digest_bytes_to_felts, felts_to_hashout, u64_to_felts},
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

/// Create a synthetic leaf node with the hash stored in the value section.
///
/// Leaf node format:
/// - [0..8]: header (type 3 = Leaf, nibble_count = 0)
/// - [8..16]: value length prefix (32 as u64 LE)
/// - [16..48]: leaf_hash (32 bytes)
/// - [48..56]: padding to felt boundary
fn create_synthetic_leaf_node(leaf_hash: &[u8; 32]) -> Vec<u8> {
    // Header: type 3 (Leaf) in bits 63-60, nibble_count = 0
    let header: u64 = 0x3000000000000000;
    let value_length: u64 = 32;

    let mut leaf_node = vec![0u8; 56];
    leaf_node[0..8].copy_from_slice(&header.to_le_bytes());
    // No nibble section since nibble_count = 0
    // Value section starts at byte 8
    leaf_node[8..16].copy_from_slice(&value_length.to_le_bytes());
    leaf_node[16..48].copy_from_slice(leaf_hash);
    // Padding bytes 48-55 are already zero

    leaf_node
}

fn synthetic_storage_proof(node_count: usize, bind_leaf: bool) -> StorageProof {
    const CHILD_HASH_OFFSET_BYTES: usize = 8; // After 8-byte length prefix in branch nodes
    const CHILD_HASH_OFFSET_HEX: usize = CHILD_HASH_OFFSET_BYTES * 2;
    const BRANCH_NODE_LEN_BYTES: usize = 48;
    const HASH_LENGTH_PREFIX: [u8; 8] = 32u64.to_le_bytes();

    // Leaf hash index: hash starts at byte 16 (after 8-byte header + 8-byte value length)
    const LEAF_HASH_OFFSET_HEX: usize = 16 * 2; // = 32

    let leaf_inputs = LeafInputs::test_inputs_0();
    let leaf_hash = if bind_leaf {
        leaf_inputs.leaf_hash()
    } else {
        [0x5a; 32]
    };

    let mut nodes = Vec::with_capacity(node_count);
    let mut indices = Vec::with_capacity(node_count);

    // First node is the leaf with hash in value section
    let leaf_node = create_synthetic_leaf_node(&leaf_hash);
    let mut child_hash = hash_node_with_poseidon_padded(&leaf_node);
    nodes.push(leaf_node);
    indices.push(LEAF_HASH_OFFSET_HEX);

    // Remaining nodes are branch nodes
    for i in 1..node_count {
        let mut node = vec![0u8; BRANCH_NODE_LEN_BYTES];
        node[..8].copy_from_slice(&HASH_LENGTH_PREFIX);
        node[8..40].copy_from_slice(&child_hash);
        node[40..].fill((i as u8).wrapping_add(17));
        child_hash = hash_node_with_poseidon_padded(&node);
        nodes.push(node);
        indices.push(CHILD_HASH_OFFSET_HEX);
    }

    nodes.reverse();
    indices.reverse();

    let processed =
        ProcessedStorageProof::new(nodes, indices).expect("synthetic proof should be well formed");
    StorageProof::new(&processed, child_hash, leaf_inputs, true)
}

fn fill_targets_unchecked(
    storage_proof: &StorageProof,
    pw: &mut plonky2::iop::witness::PartialWitness<F>,
    targets: StorageProofTargets,
) -> anyhow::Result<()> {
    use plonky2::hash::hash_types::HashOut;
    use plonky2::iop::witness::WitnessWrite;

    const EMPTY_PROOF_NODE: [F; PROOF_NODE_MAX_SIZE_F] = [F::ZERO; PROOF_NODE_MAX_SIZE_F];

    let root_hash = HashOut {
        elements: digest_bytes_to_felts(storage_proof.root_hash.try_into()?),
    };
    pw.set_hash_target(targets.root_hash, root_hash)?;
    pw.set_bool_target(targets.is_not_dummy, storage_proof.is_not_dummy)?;
    pw.set_target(
        targets.proof_len,
        F::from_canonical_usize(storage_proof.proof.len()),
    )?;

    for i in 0..MAX_PROOF_LEN {
        match storage_proof.proof.get(i) {
            Some(node) => {
                let mut padded_proof_node = node.clone();
                padded_proof_node.resize(PROOF_NODE_MAX_SIZE_F, F::ZERO);
                pw.set_target_arr(&targets.proof_data[i], &padded_proof_node)?;
            }
            None => pw.set_target_arr(&targets.proof_data[i], &EMPTY_PROOF_NODE)?,
        }
    }

    for i in 0..MAX_PROOF_LEN {
        let &felt = storage_proof.indices.get(i).unwrap_or(&F::ZERO);
        pw.set_target(targets.indices[i], felt)?;
    }

    pw.set_target(
        targets.leaf_inputs.asset_id,
        storage_proof.leaf_inputs.asset_id,
    )?;
    pw.set_target_arr(
        &targets.leaf_inputs.transfer_count,
        &storage_proof.leaf_inputs.transfer_count,
    )?;
    pw.set_hash_target(
        targets.leaf_inputs.funding_account,
        felts_to_hashout(&storage_proof.leaf_inputs.funding_account.0),
    )?;
    pw.set_hash_target(
        targets.leaf_inputs.to_account,
        felts_to_hashout(&storage_proof.leaf_inputs.to_account.0),
    )?;
    pw.set_target(
        targets.leaf_inputs.input_amount,
        storage_proof.leaf_inputs.input_amount,
    )?;
    pw.set_target(
        targets.leaf_inputs.output_amount_1,
        storage_proof.leaf_inputs.output_amount_1,
    )?;
    pw.set_target(
        targets.leaf_inputs.output_amount_2,
        storage_proof.leaf_inputs.output_amount_2,
    )?;
    pw.set_target(
        targets.leaf_inputs.volume_fee_bps,
        storage_proof.leaf_inputs.volume_fee_bps,
    )?;

    Ok(())
}

#[test]
fn build_and_verify_proof() {
    let storage_proof = StorageProof::test_inputs_0();
    run_test(&storage_proof).unwrap();
}

#[test]
fn max_safe_proof_len_still_works() {
    let storage_proof = synthetic_storage_proof(MAX_PROOF_LEN - 1, true);
    run_test(&storage_proof).unwrap();
}

#[test]
fn host_rejects_proof_len_at_maximum() {
    let storage_proof = synthetic_storage_proof(MAX_PROOF_LEN, false);
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = StorageProofTargets::new(&mut builder);

    let err = storage_proof.fill_targets(&mut pw, targets).unwrap_err();
    assert!(err
        .to_string()
        .contains("proof length exceeds maximum allowed length: 20 > 19"));
}

#[test]
fn proof_len_at_maximum_is_rejected_in_circuit() {
    let storage_proof = synthetic_storage_proof(MAX_PROOF_LEN, false);
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = StorageProofTargets::new(&mut builder);
    StorageProof::circuit(&targets, &mut builder);
    fill_targets_unchecked(&storage_proof, &mut pw, targets).unwrap();

    let err = crate::circuit_helpers::build_and_prove_test(builder, pw).unwrap_err();
    assert!(
        err.to_string().contains("partition containing Wire")
            || err
                .to_string()
                .contains("was set twice with different values")
            || err.to_string().contains("Failed"),
        "unexpected error: {err}"
    );
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
        true, // Non-zero block_hash to trigger validation
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

    let proof = StorageProof::new(
        &proof,
        default_root_hash(),
        leaf_inputs,
        true, // Non-zero block_hash to trigger validation
    );

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_exit_address() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the to account.
    leaf_inputs.to_account = SubstrateAccount::new(&[0; 32]).unwrap();

    let proof = StorageProof::new(
        &proof,
        default_root_hash(),
        leaf_inputs,
        true, // Non-zero block_hash to trigger validation
    );

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_input_amount() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the input amount (which is used for the leaf hash in storage).
    leaf_inputs.input_amount = F::from_canonical_u64(1000);

    let proof = StorageProof::new(
        &proof,
        default_root_hash(),
        leaf_inputs,
        true, // Non-zero block_hash to trigger validation
    );

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
            true, // Non-zero block_hash to trigger validation
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
