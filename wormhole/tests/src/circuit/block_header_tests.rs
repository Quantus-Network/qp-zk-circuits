use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::proof::ProofWithPublicInputs,
};
use wormhole_circuit::block_header::{BlockHeader, BlockHeaderTargets};
use zk_circuits_common::circuit::{C, D, F};

use test_helpers::TestInputs;

#[cfg(test)]
fn run_test(header: &BlockHeader) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    use zk_circuits_common::circuit::CircuitFragment as _;

    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = BlockHeaderTargets::new(&mut builder);
    BlockHeader::circuit(&targets, &mut builder);

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
    let mut raw = header.parent_hash;
    raw[0] += F::from_canonical_u64(1);
    header.parent_hash = raw;
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_state_root_fails() {
    // Same header preimage + parent hash + block number, but wrong state root public input.
    let mut header = BlockHeader::test_inputs_0();
    let mut sr = header.state_root;
    sr[0] += F::from_canonical_u64(1);
    header.state_root = sr;
    run_test(&header).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_block_number_fails() {
    // Mismatch between the felt at BLOCK_NUMBER_OFFSET and the public block number.
    let mut header = BlockHeader::test_inputs_0();
    header.block_number += F::from_canonical_u64(1);
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
fn tampered_header_preimage_fails() {
    // Change a felt in the header preimage that isn't parent/stateRoot/number limbs.
    // This changes the computed hash and should conflict with the provided block_hash.
    let mut header = BlockHeader::test_inputs_0();

    // Choose a "neutral" felt index:
    //  - 0..7   : parent hash limbs
    //  - 8      : block number limb
    //  - 9..16  : state root limbs
    //  - 17..   : free header body felts
    let idx = 20usize;
    header.block_header[idx] =
        F::from_canonical_u64(header.block_header[idx].to_canonical_u64().wrapping_add(1));

    run_test(&header).unwrap();
}

#[ignore = "performance"]
#[test]
fn fuzz_tampered_header() {
    const FUZZ_ITERATIONS: usize = 500;
    let mut panic_count = 0;

    for _ in 0..FUZZ_ITERATIONS {
        let mut header = BlockHeader::test_inputs_0();

        // Pick a felt to modify, avoiding parent(0..7), number(8), state root(9..16).
        let idx = rand::random_range(17..header.block_header.len());
        let delta = (rand::random::<u64>() % 5) + 1;
        header.block_header[idx] = F::from_canonical_u64(
            header.block_header[idx]
                .to_canonical_u64()
                .wrapping_add(delta),
        );

        let result = std::panic::catch_unwind(|| {
            run_test(&header).unwrap();
        });

        if result.is_err() {
            panic_count += 1;
        }
    }

    assert_eq!(
        panic_count, FUZZ_ITERATIONS,
        "Only {panic_count} out of {FUZZ_ITERATIONS} iterations panicked"
    );
}
