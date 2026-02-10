use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use wormhole_circuit::block_header::{add_block_hash_validation, BlockHeader, BlockHeaderTargets};
use zk_circuits_common::circuit::{C, D, F};

use test_helpers::TestInputs;

#[cfg(test)]
fn run_test(header: &BlockHeader) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    use zk_circuits_common::circuit::CircuitFragment as _;

    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = BlockHeaderTargets::new(&mut builder);
    BlockHeader::circuit(&targets, &mut builder);
    // Add block hash validation for isolated testing
    add_block_hash_validation(&targets, &mut builder);

    header.fill_targets(&mut pw, targets).unwrap();
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_block_header_0() {
    let header = BlockHeader::test_inputs_0();
    run_test(&header).unwrap();
}

#[test]
fn build_and_verify_block_header_1() {
    let header = BlockHeader::test_inputs_1();
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_parent_hash_fails() {
    // Same header preimage + block number + state root, but wrong parent hash public input.
    let mut header = BlockHeader::test_inputs_0();
    // Flip 1 byte in the parent hash digest exposed as public input.
    let mut raw = header.header.parent_hash;
    raw[0] += F::from_canonical_u64(1);
    header.header.parent_hash = raw;
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_state_root_fails() {
    // Same header preimage + parent hash + block number, but wrong state root public input.
    let mut header = BlockHeader::test_inputs_0();
    let mut sr = header.header.state_root;
    sr[0] += F::from_canonical_u64(1);
    header.header.state_root = sr;
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_block_number_fails() {
    // Mismatch between the felt at BLOCK_NUMBER_OFFSET and the public block number.
    let mut header = BlockHeader::test_inputs_0();
    header.header.block_number += F::from_canonical_u64(1);
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_block_hash_fails() {
    // Provide a wrong block_hash public input (while header preimage stays the same).
    let mut header = BlockHeader::test_inputs_0();
    let mut bh = header.block_hash;
    bh[0] += F::from_canonical_u64(1);
    header.block_hash = bh;
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_extrinsic_hash_fails() {
    let mut header = BlockHeader::test_inputs_0();

    let mut sr = header.header.extrinsics_root;
    sr[0] += F::from_canonical_u64(1);
    header.header.extrinsics_root = sr;
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_digest_fails() {
    let mut header = BlockHeader::test_inputs_0();

    let mut sr = header.header.digest;
    sr[0] += F::from_canonical_u64(1);
    header.header.digest = sr;
    run_test(&header).unwrap();
}
