use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::{
    hash::poseidon2::Poseidon2Hash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::Hasher,
        proof::ProofWithPublicInputs,
    },
};
use qp_wormhole_inputs::{BytesDigest, PrivateBatchShape, WithdrawalOutput};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};
use zk_circuits_common::utils::bytes_to_digest;

use crate::private_batch::{
    circuit::{
        circuit_logic::{PrivateBatchCircuit, PrivateBatchCircuitTargets},
        constants::{
            aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START,
            INPUT_AMOUNT_START, LEAF_PI_LEN, NULLIFIER_START,
        },
    },
    prover::witness::fill_private_batch_witness,
};

use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

const TEST_ASSET_ID: u64 = 0;
const TEST_VOLUME_FEE_BPS: u32 = 10; // 0.1% = 10 bps
const TEST_BLOCK_NUMBER: u64 = 42;

// ---------------- Leaf PI helpers ----------------

fn nullifier(i: usize) -> [F; 4] {
    core::array::from_fn(|j| {
        F::from_canonical_u64(0x90A0_0001_0000_0000 + (i as u64) * 16 + j as u64)
    })
}

fn block_hash(i: usize) -> [F; 4] {
    core::array::from_fn(|j| {
        F::from_canonical_u64(0xAAAA_0001_0000_0000 + (i as u64) * 16 + j as u64)
    })
}

fn exit_account(i: u8) -> BytesDigest {
    BytesDigest::try_from([0x10 + i; 32]).unwrap()
}

fn output(account: u8, amount: u32) -> WithdrawalOutput {
    WithdrawalOutput {
        exit_account: exit_account(account),
        amount,
    }
}

/// A real leaf: `input_amount` burned at `block`, spending `nullifier`.
fn real_leaf_pis(
    asset_id: u64,
    input_amount: u64,
    nullifier: [F; 4],
    block: [F; 4],
) -> [F; LEAF_PI_LEN] {
    let mut out = [F::ZERO; LEAF_PI_LEN];
    out[ASSET_ID_START] = F::from_canonical_u64(asset_id);
    out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
    out[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&block);
    out[BLOCK_NUMBER_START] = F::from_canonical_u64(TEST_BLOCK_NUMBER);
    out[INPUT_AMOUNT_START] = F::from_canonical_u64(input_amount);
    out
}

/// A dummy leaf: zero block hash sentinel. The nullifier field is ignored by
/// the wrapper (replaced with a hash of a fresh preimage).
fn dummy_leaf_pis(asset_id: u64, nullifier: [F; 4]) -> [F; LEAF_PI_LEN] {
    real_leaf_pis(asset_id, 0, nullifier, [F::ZERO; 4])
}

// ---------------- Circuit helpers ----------------

fn build_private_batch(
    leaf: &CircuitData<F, C, D>,
    shape: PrivateBatchShape,
) -> (CircuitData<F, C, D>, PrivateBatchCircuitTargets) {
    let circuit = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf.common,
        &leaf.verifier_only,
        shape,
    )
    .unwrap();
    let targets = circuit.targets();
    (circuit.build_circuit(), targets)
}

fn deterministic_dummy_nullifier_pre_images(n: usize) -> Vec<[F; 4]> {
    let mut rng = StdRng::from_seed([77u8; 32]);
    (0..n)
        .map(|_| core::array::from_fn(|_| F::from_canonical_u64(rng.gen::<u32>() as u64)))
        .collect()
}

/// Prove one private batch, padding `outputs` with zero slots up to the
/// circuit's exit-slot count, with the identity nullifier permutation.
fn prove_private_batch(
    data: &CircuitData<F, C, D>,
    targets: &PrivateBatchCircuitTargets,
    proofs: &[ProofWithPublicInputs<F, C, D>],
    outputs: &[WithdrawalOutput],
    volume_fee_bps: u32,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let permutation: Vec<usize> = (0..proofs.len()).collect();
    prove_private_batch_with_permutation(
        data,
        targets,
        proofs,
        outputs,
        volume_fee_bps,
        &permutation,
    )
}

fn prove_private_batch_with_permutation(
    data: &CircuitData<F, C, D>,
    targets: &PrivateBatchCircuitTargets,
    proofs: &[ProofWithPublicInputs<F, C, D>],
    outputs: &[WithdrawalOutput],
    volume_fee_bps: u32,
    nullifier_permutation: &[usize],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut padded_outputs = outputs.to_vec();
    padded_outputs.resize(targets.exit_slots.len(), WithdrawalOutput::default());
    let mut pw = PartialWitness::new();
    fill_private_batch_witness(
        &mut pw,
        targets,
        proofs,
        &padded_outputs,
        volume_fee_bps,
        &deterministic_dummy_nullifier_pre_images(proofs.len()),
        nullifier_permutation,
    )?;
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok(proof)
}

fn hash_dummy_nullifier_pre_image_native(pre_image: [F; 4]) -> [F; 4] {
    let inner_hash = Poseidon2Hash::hash_no_pad(&pre_image).elements;
    Poseidon2Hash::hash_no_pad(&inner_hash).elements
}

// ---------------- Output PI readers ----------------

fn header_block_hash(pis: &[F]) -> [F; 4] {
    core::array::from_fn(|j| pis[aggregated_output::BLOCK_HASH_OFFSET + j])
}

/// Read the exit-slot region as `(amount, exit_account)` pairs.
fn exit_slots(pis: &[F], shape: PrivateBatchShape) -> Vec<(F, [F; 4])> {
    let start = aggregated_output::exit_slots_start();
    (0..shape.num_exit_slots)
        .map(|i| {
            let base = start + i * aggregated_output::EXIT_SLOT_LEN;
            (pis[base], core::array::from_fn(|j| pis[base + 1 + j]))
        })
        .collect()
}

fn expected_slot(out: &WithdrawalOutput) -> (F, [F; 4]) {
    (
        F::from_canonical_u32(out.amount),
        bytes_to_digest(out.exit_account),
    )
}

/// Read the nullifier region (`num_leaf_proofs` entries of 4 felts).
fn nullifier_region(pis: &[F], shape: PrivateBatchShape) -> Vec<[F; 4]> {
    let start = aggregated_output::nullifiers_start(shape);
    (0..shape.num_leaf_proofs)
        .map(|i| core::array::from_fn(|j| pis[start + i * 4 + j]))
        .collect()
}

// =========================================================================
// Fee / amount constraints
// =========================================================================

#[test]
fn aggregate_fee_regressions() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(7, 7);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);

    // `inputs[i]` is burned by real leaf i; remaining slots are dummies, the
    // first of which carries `dummy_input` as its (masked) input amount.
    let prove_case =
        |inputs: &[u64], outputs: &[u32], fee_bps: u32, dummy_input: u64| -> Result<_> {
            let mut proofs: Vec<_> = inputs
                .iter()
                .enumerate()
                .map(|(i, &input)| {
                    prove_fake_leaf(
                        &leaf_data,
                        &leaf_targets,
                        real_leaf_pis(0, input, nullifier(i), block),
                    )
                })
                .collect();
            for i in inputs.len()..SHAPE.num_leaf_proofs {
                let mut pis = dummy_leaf_pis(0, nullifier(i));
                if i == inputs.len() {
                    pis[INPUT_AMOUNT_START] = F::from_canonical_u64(dummy_input);
                }
                proofs.push(prove_fake_leaf(&leaf_data, &leaf_targets, pis));
            }
            let outputs: Vec<_> = outputs
                .iter()
                .enumerate()
                .map(|(i, &amount)| output(i as u8, amount))
                .collect();
            prove_private_batch(&data, &targets, &proofs, &outputs, fee_bps)
        };

    assert!(
        prove_case(&[100, 1, 1, 1, 1], &[20, 20, 20, 20, 23], 4, 0).is_ok(),
        "103q out from 104q in must pay the 1q segment fee"
    );
    assert!(
        prove_case(&[100, 1, 1, 1, 1], &[20, 20, 20, 20, 24], 4, 0).is_err(),
        "104q out from 104q in must not bypass the fee"
    );
    assert!(
        prove_case(&[2_500], &[2_499], 4, 0).is_ok(),
        "2499q out requires exactly 2500q in at 4 bps"
    );
    assert!(
        prove_case(&[2_499], &[2_499], 4, 0).is_err(),
        "a one-real-leaf segment must still pay its ceiling fee"
    );
    assert!(
        prove_case(&[2, 2, 2, 2, 2, 2, 2], &[2, 2, 2, 2, 2, 2, 1], 4, 0).is_ok(),
        "13q out from 14q in must be valid with one aggregate fee quantum"
    );
    assert!(
        prove_case(&[1], &[1], 4, u32::MAX as u64).is_err(),
        "dummy input value must not subsidize a real exit"
    );
    assert!(
        prove_case(&[100], &[100], 0, 0).is_ok() && prove_case(&[99], &[100], 0, 0).is_err(),
        "zero-fee batches must enforce total output <= total input"
    );
    assert!(
        prove_case(&[10_000], &[1], 9_999, 0).is_ok()
            && prove_case(&[9_999], &[1], 9_999, 0).is_err(),
        "9999 bps must use a denominator of one"
    );
    assert!(
        prove_case(&[0], &[0], 10_000, 0).is_ok()
            && prove_case(&[u32::MAX as u64], &[1], 10_000, 0).is_err(),
        "10000 bps must allow only zero aggregate output"
    );
    assert!(
        prove_case(&[2_500], &[1_249, 1_250], 4, 0).is_ok()
            && prove_case(&[2_499], &[1_249, 1_250], 4, 0).is_err(),
        "one burn split across several outputs must pay the fee on the total"
    );
    assert!(
        prove_case(&[1_000, 1_000, 500], &[2_499], 4, 0).is_ok()
            && prove_case(&[1_000, 1_000, 499], &[2_499], 4, 0).is_err(),
        "several burns pooled into one output must pay the fee on the total"
    );

    let max = u32::MAX;
    assert!(
        prove_case(&[max as u64; 7], &[max - 2_000_000; 7], 4, 0).is_ok(),
        "large valid totals must not wrap the field or the 52-bit difference check"
    );
    assert!(
        prove_case(&[0; 7], &[max; 7], 0, 0).is_err(),
        "a large negative integer fee difference must not pass through field wraparound"
    );
    assert!(
        prove_case(&[1], &[0], 10_001, 0).is_err(),
        "the aggregate fee rate must remain bounded by 10000 bps"
    );
}

/// Exit amounts are prover-chosen witnesses, so each must be range-checked to
/// 32 bits before being summed into the fee constraint.
#[test]
fn exit_amount_above_u32_fails() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(1, 2);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let proof = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        real_leaf_pis(0, u32::MAX as u64, nullifier(0), block_hash(0)),
    );

    // Bypass the u32-typed witness API to feed a 2^32 amount directly; with a
    // zero fee it would satisfy `total_output <= total_input` only if the
    // field-level sum were trusted (u32::MAX + 2^32 + ... wraps nowhere near).
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&targets.leaf_proofs[0], &proof)
        .unwrap();
    set_batch_witnesses(
        &mut pw,
        &targets,
        &[F::from_canonical_u64(1 << 32), F::ZERO],
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(pw)));
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "a 2^32 exit amount must fail the 32-bit range check"
    );
}

#[test]
fn private_batch_masking_uniqueness_and_privacy_regressions() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(2, 2);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);

    let prove_pis = |pis_list: Vec<[F; LEAF_PI_LEN]>, outputs: &[WithdrawalOutput], fee: u32| {
        let proofs = pis_list
            .into_iter()
            .map(|pis| prove_fake_leaf(&leaf_data, &leaf_targets, pis))
            .collect::<Vec<_>>();
        prove_private_batch(&data, &targets, &proofs, outputs, fee)
    };

    assert!(
        prove_pis(
            vec![
                real_leaf_pis(0, 1, nullifier(0), block),
                real_leaf_pis(0, 1, nullifier(0), block),
            ],
            &[output(0, 1), output(1, 1)],
            0,
        )
        .is_err(),
        "the circuit must reject duplicate real nullifiers without relying on prover preflight"
    );

    // A dummy leaf carrying a huge input amount must not fund any output.
    let mut poisoned_dummy = dummy_leaf_pis(0, nullifier(0));
    poisoned_dummy[INPUT_AMOUNT_START] = F::from_canonical_u32(u32::MAX);
    assert!(
        prove_pis(
            vec![
                poisoned_dummy,
                real_leaf_pis(0, 10_000, nullifier(1), block)
            ],
            &[output(0, 9_996)],
            4,
        )
        .is_ok(),
        "the real leaf alone covers 9996 at 4 bps"
    );
    assert!(
        prove_pis(
            vec![
                poisoned_dummy,
                real_leaf_pis(0, 10_000, nullifier(1), block)
            ],
            &[output(0, 9_997)],
            4,
        )
        .is_err(),
        "a dummy slot's input amount must be masked out of the fee check"
    );

    let public_inputs_for = |inputs: [u64; 2]| {
        prove_pis(
            vec![
                real_leaf_pis(0, inputs[0], nullifier(0), block),
                real_leaf_pis(0, inputs[1], nullifier(1), block),
            ],
            &[output(0, 20), output(1, 30)],
            0,
        )
        .unwrap()
        .public_inputs
    };
    assert_eq!(
        public_inputs_for([20, 30]),
        public_inputs_for([200, 300]),
        "leaf input amounts must be consumed by the wrapper without being forwarded"
    );
}

#[test]
#[ignore = "slow: builds and proves the maximum 64-leaf / 64-slot recursive circuit"]
fn maximum_width_private_batch_fee_does_not_wrap() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(64, 64);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let block = block_hash(0);
    let max = u32::MAX;
    let proofs = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            prove_fake_leaf(
                &leaf_data,
                &leaf_targets,
                real_leaf_pis(0, max as u64, nullifier(i), block),
            )
        })
        .collect::<Vec<_>>();
    let outputs: Vec<_> = (0..SHAPE.num_exit_slots)
        .map(|i| output(i as u8, max - 2_000_000))
        .collect();

    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    prove_private_batch(&data, &targets, &proofs, &outputs, 4).unwrap();
}

// =========================================================================
// End-to-end aggregation
// =========================================================================

#[test]
fn recursive_aggregation_tree() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(8, 5);
    let mut rng = StdRng::from_seed([41u8; 32]);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);

    let inputs: Vec<u32> = (0..SHAPE.num_leaf_proofs)
        .map(|_| rng.gen::<u32>() >> 4)
        .collect();
    let proofs: Vec<_> = inputs
        .iter()
        .enumerate()
        .map(|(i, &input)| {
            prove_fake_leaf(
                &leaf_data,
                &leaf_targets,
                real_leaf_pis(TEST_ASSET_ID, input as u64, nullifier(i), block),
            )
        })
        .collect();

    // Spend everything the fee allows across 4 of the 5 slots.
    let total_input: u64 = inputs.iter().map(|&x| x as u64).sum();
    let max_output = total_input * (10_000 - TEST_VOLUME_FEE_BPS as u64) / 10_000;
    let per_output = (max_output / 4) as u32;
    let outputs: Vec<_> = (0..4).map(|i| output(i as u8, per_output)).collect();

    let root_proof =
        prove_private_batch(&data, &targets, &proofs, &outputs, TEST_VOLUME_FEE_BPS).unwrap();
    let pis = &root_proof.public_inputs;

    assert_eq!(pis.len(), aggregated_output::pi_len(SHAPE));
    assert_eq!(
        pis[aggregated_output::NUM_EXIT_SLOTS_OFFSET].to_canonical_u64() as usize,
        SHAPE.num_exit_slots
    );
    assert_eq!(
        pis[aggregated_output::ASSET_ID_OFFSET].to_canonical_u64(),
        TEST_ASSET_ID
    );
    assert_eq!(
        pis[aggregated_output::VOLUME_FEE_BPS_OFFSET].to_canonical_u64(),
        TEST_VOLUME_FEE_BPS as u64
    );
    assert_eq!(header_block_hash(pis), block);
    assert_eq!(
        pis[aggregated_output::BLOCK_NUMBER_OFFSET].to_canonical_u64(),
        TEST_BLOCK_NUMBER
    );

    let mut expected_slots: Vec<_> = outputs.iter().map(expected_slot).collect();
    expected_slots.push((F::ZERO, [F::ZERO; 4]));
    assert_eq!(exit_slots(pis, SHAPE), expected_slots);

    // The test helper witnesses the identity permutation.
    let expected_nullifiers: Vec<[F; 4]> = (0..SHAPE.num_leaf_proofs).map(nullifier).collect();
    assert_eq!(nullifier_region(pis, SHAPE), expected_nullifiers);
}

#[test]
fn recursive_aggregation_tree_different_blocks_fails() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(4, 1);
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);

    let proofs: Vec<_> = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            prove_fake_leaf(
                &leaf_data,
                &leaf_targets,
                real_leaf_pis(TEST_ASSET_ID, 100, nullifier(i), block_hash(i)),
            )
        })
        .collect();

    assert!(
        prove_private_batch(&data, &targets, &proofs, &[], 0).is_err(),
        "expected failure because proofs are from different blocks"
    );
}

#[test]
fn recursive_aggregation_tree_mismatched_asset_id_fails() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(4, 1);
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);

    let proofs: Vec<_> = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            let asset_id = if i == 2 { 9 } else { 7 };
            prove_fake_leaf(
                &leaf_data,
                &leaf_targets,
                real_leaf_pis(asset_id, 100, nullifier(i), block),
            )
        })
        .collect();

    assert!(
        prove_private_batch(&data, &targets, &proofs, &[], 0).is_err(),
        "expected failure due to mismatched asset IDs"
    );
}

#[test]
fn recursive_aggregation_tree_with_dummy_proofs() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(8, 3);
    const NUM_REAL: usize = 2;

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);

    let proofs: Vec<_> = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            let pis = if i < NUM_REAL {
                real_leaf_pis(TEST_ASSET_ID, 1_000, nullifier(i), block)
            } else {
                dummy_leaf_pis(TEST_ASSET_ID, nullifier(i))
            };
            prove_fake_leaf(&leaf_data, &leaf_targets, pis)
        })
        .collect();

    let outputs = [output(0, 1_500), output(1, 498)];
    let root_proof =
        prove_private_batch(&data, &targets, &proofs, &outputs, TEST_VOLUME_FEE_BPS).unwrap();
    let pis = &root_proof.public_inputs;

    assert_eq!(header_block_hash(pis), block);
    assert_eq!(
        pis[aggregated_output::BLOCK_NUMBER_OFFSET].to_canonical_u64(),
        TEST_BLOCK_NUMBER
    );

    let mut expected_slots: Vec<_> = outputs.iter().map(expected_slot).collect();
    expected_slots.push((F::ZERO, [F::ZERO; 4]));
    assert_eq!(exit_slots(pis, SHAPE), expected_slots);

    // The test helper witnesses the identity permutation.
    let pre_images = deterministic_dummy_nullifier_pre_images(SHAPE.num_leaf_proofs);
    let expected: Vec<[F; 4]> = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            if i < NUM_REAL {
                nullifier(i)
            } else {
                hash_dummy_nullifier_pre_image_native(pre_images[i])
            }
        })
        .collect();
    assert_eq!(
        nullifier_region(pis, SHAPE),
        expected,
        "nullifier region must preserve real and dummy-replacement nullifiers"
    );
    for original in (NUM_REAL..SHAPE.num_leaf_proofs).map(nullifier) {
        assert!(
            !nullifier_region(pis, SHAPE).contains(&original),
            "original dummy nullifier must be replaced, not forwarded"
        );
    }
}

/// The circuit must accept the real proof in EVERY slot position. The block
/// reference is selected in-circuit from the first non-dummy slot, so any slot
/// order (uniform shuffle) must be satisfiable without leaking which slot is real.
#[test]
fn recursive_aggregation_real_proof_in_every_slot_succeeds() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(4, 1);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);
    let pre_images = deterministic_dummy_nullifier_pre_images(SHAPE.num_leaf_proofs);

    for real_slot in 0..SHAPE.num_leaf_proofs {
        let proofs: Vec<_> = (0..SHAPE.num_leaf_proofs)
            .map(|i| {
                let pis = if i == real_slot {
                    real_leaf_pis(TEST_ASSET_ID, 500, nullifier(i), block)
                } else {
                    dummy_leaf_pis(TEST_ASSET_ID, nullifier(i))
                };
                prove_fake_leaf(&leaf_data, &leaf_targets, pis)
            })
            .collect();

        let root_proof = prove_private_batch(
            &data,
            &targets,
            &proofs,
            &[output(0, 499)],
            TEST_VOLUME_FEE_BPS,
        )
        .unwrap_or_else(|e| {
            panic!("aggregation with real proof in slot {real_slot} must be satisfiable: {e}")
        });
        let pis = &root_proof.public_inputs;

        assert_eq!(
            header_block_hash(pis),
            block,
            "block reference must come from the real slot {real_slot}"
        );
        assert_eq!(
            pis[aggregated_output::BLOCK_NUMBER_OFFSET].to_canonical_u64(),
            TEST_BLOCK_NUMBER
        );

        let expected: Vec<[F; 4]> = (0..SHAPE.num_leaf_proofs)
            .map(|i| {
                if i == real_slot {
                    nullifier(i)
                } else {
                    hash_dummy_nullifier_pre_image_native(pre_images[i])
                }
            })
            .collect();
        assert_eq!(
            nullifier_region(pis, SHAPE),
            expected,
            "nullifier region mismatch with real proof in slot {real_slot}"
        );
    }
}

#[test]
fn recursive_aggregation_tree_all_dummy_proofs() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(8, 2);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let proofs: Vec<_> = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            prove_fake_leaf(
                &leaf_data,
                &leaf_targets,
                dummy_leaf_pis(TEST_ASSET_ID, nullifier(i)),
            )
        })
        .collect();

    let root_proof =
        prove_private_batch(&data, &targets, &proofs, &[], TEST_VOLUME_FEE_BPS).unwrap();
    let pis = &root_proof.public_inputs;

    assert_eq!(
        header_block_hash(pis),
        [F::ZERO; 4],
        "all-dummy batch should have zero block hash"
    );
    assert!(exit_slots(pis, SHAPE)
        .iter()
        .all(|slot| *slot == (F::ZERO, [F::ZERO; 4])));

    let expected: Vec<[F; 4]> = deterministic_dummy_nullifier_pre_images(SHAPE.num_leaf_proofs)
        .iter()
        .map(|p| hash_dummy_nullifier_pre_image_native(*p))
        .collect();
    assert_eq!(
        nullifier_region(pis, SHAPE),
        expected,
        "all-dummy nullifier region must contain the replacement hashes"
    );

    assert!(
        prove_private_batch(&data, &targets, &proofs, &[output(0, 1)], 0).is_err(),
        "an all-dummy batch burns nothing and must not fund any output"
    );
}

/// The private switch witness may route the verified nullifier multiset into
/// any requested order without changing any digest contents.
#[test]
fn nullifier_region_follows_private_permutation() {
    const SHAPE: PrivateBatchShape = PrivateBatchShape::new(4, 1);

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let (data, targets) = build_private_batch(&leaf_data, SHAPE);
    let block = block_hash(0);
    let proofs: Vec<_> = (0..SHAPE.num_leaf_proofs)
        .map(|i| {
            prove_fake_leaf(
                &leaf_data,
                &leaf_targets,
                real_leaf_pis(TEST_ASSET_ID, 100, nullifier(i), block),
            )
        })
        .collect();

    let permutation = vec![2, 0, 3, 1];
    let root_proof =
        prove_private_batch_with_permutation(&data, &targets, &proofs, &[], 0, &permutation)
            .unwrap();

    let got = nullifier_region(&root_proof.public_inputs, SHAPE);
    let expected: Vec<[F; 4]> = permutation.iter().map(|&i| nullifier(i)).collect();
    assert_eq!(
        got, expected,
        "nullifier region must follow the private permutation exactly"
    );
}

// =========================================================================
// Security tests: Verifier key substitution attack prevention
// =========================================================================

/// Build a MALICIOUS circuit - same PI count as leaf, but NO security constraints.
fn build_malicious_leaf_circuit() -> (CircuitData<F, C, D>, Vec<Target>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let pis: Vec<_> = (0..LEAF_PI_LEN)
        .map(|_| builder.add_virtual_target())
        .collect();

    // NO constraints! Attacker can set any values.

    let targets = pis.clone();
    builder.register_public_inputs(&pis);
    (builder.build::<C>(), targets)
}

/// Set every non-proof witness target directly: zero fee, zero exit accounts,
/// the given per-slot amounts, fixed dummy preimages. Only valid for shapes
/// with a single leaf (no permutation switches).
fn set_batch_witnesses(
    pw: &mut PartialWitness<F>,
    targets: &PrivateBatchCircuitTargets,
    amounts: &[F],
) {
    assert!(targets.nullifier_permutation_switches.is_empty());
    pw.set_target(targets.volume_fee_bps, F::ZERO).unwrap();
    for (slot, amount) in targets.exit_slots.iter().zip(amounts) {
        pw.set_target(slot.amount, *amount).unwrap();
        for t in slot.exit_account {
            pw.set_target(t, F::ZERO).unwrap();
        }
    }
    for pre_image in &targets.dummy_nullifier_pre_images {
        for (i, &t) in pre_image.iter().enumerate() {
            pw.set_target(t, F::from_canonical_u64(i as u64)).unwrap();
        }
    }
}

/// Test that private-batch rejects proofs from a malicious circuit when built with
/// the legitimate verifier key baked in as constants.
#[test]
fn private_batch_rejects_malicious_circuit_proofs() {
    let (legit_circuit, _legit_targets) = build_fake_leaf_circuit();
    let (malicious_circuit, malicious_targets) = build_malicious_leaf_circuit();

    let private_batch_circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &legit_circuit.common,
        &legit_circuit.verifier_only, // SECURITY: Baked as constants
        PrivateBatchShape::new(1, 1),
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    let mut fake_pis = real_leaf_pis(999, 0xFFFF_FFFF, nullifier(0), block_hash(0));
    fake_pis[1] = F::from_canonical_u64(0xFFFF_FFFF); // would fail range_check in legit circuit
    let mut pw = PartialWitness::new();
    for (t, v) in malicious_targets.iter().zip(fake_pis) {
        pw.set_target(*t, v).unwrap();
    }
    let malicious_proof = malicious_circuit.prove(pw).expect("prove malicious");

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&private_batch_targets.leaf_proofs[0], &malicious_proof)
        .unwrap();
    set_batch_witnesses(&mut pw, &private_batch_targets, &[F::ZERO]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        private_batch_data.prove(pw)
    }));
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "private-batch should reject proofs from malicious circuit"
    );
}

/// Test that private-batch correctly accepts legitimate proofs with the baked-in key.
#[test]
fn private_batch_accepts_legitimate_proofs_after_fix() {
    let (legit_circuit, legit_targets) = build_fake_leaf_circuit();

    let private_batch_circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &legit_circuit.common,
        &legit_circuit.verifier_only,
        PrivateBatchShape::new(1, 1),
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    let legit_proof = prove_fake_leaf(
        &legit_circuit,
        &legit_targets,
        real_leaf_pis(0, 3_031, nullifier(0), block_hash(0)),
    );

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&private_batch_targets.leaf_proofs[0], &legit_proof)
        .unwrap();
    set_batch_witnesses(&mut pw, &private_batch_targets, &[F::ZERO]);

    let private_batch_proof = private_batch_data
        .prove(pw)
        .expect("private-batch prove should succeed");
    private_batch_data
        .verify(private_batch_proof)
        .expect("private-batch verify should succeed");
}

/// Audit finding: the constructor forwarded the caller-supplied
/// `CircuitConfig` to `CircuitBuilder::new` unchecked. Structurally
/// impossible configs (e.g. `num_wires` below the Poseidon gate floor)
/// panicked deep inside plonky2 mid-construction, and resource-pathological
/// configs (e.g. an oversized FRI rate driving `2^(degree_bits+rate_bits)`
/// LDE allocations) sailed through construction and only exploded during
/// the expensive build/prove phase. Both classes must be rejected with a
/// controlled error before any builder work.
#[test]
fn new_rejects_pathological_circuit_configs() {
    let (leaf, _) = build_fake_leaf_circuit();
    let shape = PrivateBatchShape::new(1, 1);

    // Structurally impossible: below the Poseidon gate wire floor.
    let mut narrow = wormhole_private_batch_circuit_config();
    narrow.num_wires = 134;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PrivateBatchCircuit::new(narrow, &leaf.common, &leaf.verifier_only, shape)
    }));
    let err = result
        .expect("pathological num_wires must yield a controlled error, not a panic")
        .err()
        .expect("num_wires below the Poseidon gate floor must be rejected");
    assert!(err.to_string().contains("num_wires"), "got: {err}");

    // Resource-pathological: oversized FRI rate (exponential LDE size).
    let mut huge_rate = wormhole_private_batch_circuit_config();
    huge_rate.fri_config.rate_bits = 63;
    let err = PrivateBatchCircuit::new(huge_rate, &leaf.common, &leaf.verifier_only, shape)
        .err()
        .expect("oversized rate_bits must be rejected before construction");
    assert!(err.to_string().contains("rate_bits"), "got: {err}");
}

#[test]
fn new_rejects_out_of_range_shapes() {
    use qp_wormhole_inputs::MAX_PROOF_COUNT;
    let (leaf, _) = build_fake_leaf_circuit();

    for (shape, field) in [
        (PrivateBatchShape::new(0, 1), "num_leaf_proofs"),
        (
            PrivateBatchShape::new(MAX_PROOF_COUNT + 1, 1),
            "num_leaf_proofs",
        ),
        (PrivateBatchShape::new(1, 0), "num_exit_slots"),
        (
            PrivateBatchShape::new(1, MAX_PROOF_COUNT + 1),
            "num_exit_slots",
        ),
    ] {
        let err = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            shape,
        )
        .err()
        .unwrap_or_else(|| panic!("{shape:?} must be rejected"));
        assert!(err.to_string().contains(field), "got: {err}");
    }
}

/// The constructor must reject inner circuits whose public-input length
/// doesn't match the fixed leaf layout with a normal error, not a
/// panic mid-construction (the wrapper indexes fixed PI offsets).
#[test]
fn new_rejects_non_leaf_shaped_inner_circuit() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let ts = builder.add_virtual_targets(5);
    builder.register_public_inputs(&ts);
    let wrong_shape = builder.build::<C>();

    let err = PrivateBatchCircuit::new(
        config,
        &wrong_shape.common,
        &wrong_shape.verifier_only,
        PrivateBatchShape::new(1, 1),
    )
    .err()
    .expect("non-leaf-shaped inner circuit must be rejected");
    assert!(err.to_string().contains("num_public_inputs"), "got: {err}");
}

// -------------------------------------------------------------------------
// Witness-fill preflight
//
// A proof with the expected public-input count can still carry internally
// inconsistent proof vectors. The pinned qp-plonky2 witness writer assigns
// those through zip_eq / debug-only length checks, so without a full shape
// preflight a malformed proof panics inside fill_private_batch_witness
// (or silently leaves targets unset) instead of returning Err.
// -------------------------------------------------------------------------

/// Prove one valid fake leaf and build matching 1-leaf / 1-slot private-batch targets.
fn valid_leaf_proof_and_targets() -> (ProofWithPublicInputs<F, C, D>, PrivateBatchCircuitTargets) {
    let (leaf, leaf_targets) = build_fake_leaf_circuit();
    let proof = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; LEAF_PI_LEN]);

    let targets = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        PrivateBatchShape::new(1, 1),
    )
    .unwrap()
    .targets();

    (proof, targets)
}

fn fill_witness_with(
    targets: &PrivateBatchCircuitTargets,
    proof: ProofWithPublicInputs<F, C, D>,
    outputs: &[WithdrawalOutput],
    permutation: &[usize],
) -> Result<()> {
    let mut pw = PartialWitness::new();
    fill_private_batch_witness(
        &mut pw,
        targets,
        &[proof],
        outputs,
        0,
        &deterministic_dummy_nullifier_pre_images(1),
        permutation,
    )
}

fn fill_witness_with_proof(
    targets: &PrivateBatchCircuitTargets,
    proof: ProofWithPublicInputs<F, C, D>,
) -> Result<()> {
    fill_witness_with(targets, proof, &[WithdrawalOutput::default()], &[0])
}

/// Control: an untampered proof must still pass the shape preflight.
#[test]
fn witness_fill_accepts_well_shaped_proof() {
    let (proof, targets) = valid_leaf_proof_and_targets();
    fill_witness_with_proof(&targets, proof)
        .expect("a valid, well-shaped proof must fill the witness");
}

#[test]
fn witness_fill_rejects_wrong_pi_length_proof() {
    let (mut proof, targets) = valid_leaf_proof_and_targets();
    proof.public_inputs.pop();

    let err = fill_witness_with_proof(&targets, proof)
        .expect_err("truncated proof public inputs must be rejected");
    assert!(err.to_string().contains("public inputs"), "got: {err}");
}

#[test]
fn witness_fill_rejects_wrong_output_count() {
    let (proof, targets) = valid_leaf_proof_and_targets();

    let err = fill_witness_with(&targets, proof.clone(), &[], &[0])
        .expect_err("too few outputs must be rejected");
    assert!(
        err.to_string().contains("output count mismatch"),
        "got: {err}"
    );

    let err = fill_witness_with(&targets, proof, &[output(0, 1), output(1, 1)], &[0])
        .expect_err("too many outputs must be rejected");
    assert!(
        err.to_string().contains("output count mismatch"),
        "got: {err}"
    );
}

#[test]
fn witness_fill_rejects_invalid_nullifier_permutation() {
    let (proof, targets) = valid_leaf_proof_and_targets();

    let err = fill_witness_with(&targets, proof.clone(), &[WithdrawalOutput::default()], &[])
        .expect_err("short nullifier permutation must be rejected");
    assert!(err.to_string().contains("length mismatch"), "got: {err}");

    let err = fill_witness_with(&targets, proof, &[WithdrawalOutput::default()], &[1])
        .expect_err("out-of-range nullifier permutation index must be rejected");
    assert!(err.to_string().contains("every input index"), "got: {err}");
}

/// A shortened FRI query-round list panics in plonky2's zip_eq without a
/// shape preflight; it must instead be rejected with an error.
#[test]
fn witness_fill_rejects_truncated_fri_query_rounds() {
    let (mut proof, targets) = valid_leaf_proof_and_targets();
    proof.proof.opening_proof.query_round_proofs.pop();

    let err = fill_witness_with_proof(&targets, proof)
        .expect_err("proof with truncated FRI query rounds must be rejected");
    assert!(err.to_string().contains("query_round_proofs"), "got: {err}");
}

/// A truncated opening set trips a debug-only length check in plonky2's
/// witness writer (silent partial assignment in release); it must instead
/// be rejected with an error.
#[test]
fn witness_fill_rejects_truncated_openings() {
    let (mut proof, targets) = valid_leaf_proof_and_targets();
    proof.proof.openings.wires.pop();

    let err = fill_witness_with_proof(&targets, proof)
        .expect_err("proof with truncated openings must be rejected");
    assert!(err.to_string().contains("openings.wires"), "got: {err}");
}

/// A shortened wires Merkle cap is assigned through a plain zip, silently
/// leaving trailing cap targets unset and deferring failure to prove time;
/// it must instead be rejected with an error.
#[test]
fn witness_fill_rejects_truncated_wires_cap() {
    let (mut proof, targets) = valid_leaf_proof_and_targets();
    proof.proof.wires_cap.0.pop();

    let err = fill_witness_with_proof(&targets, proof)
        .expect_err("proof with truncated wires_cap must be rejected");
    assert!(err.to_string().contains("wires_cap"), "got: {err}");
}

// -------------------------------------------------------------------------
// Formal export
// -------------------------------------------------------------------------

/// Builds only the wrapper logic (no recursive verifiers) on virtual proof / PI
/// targets, at `n = 2`, and reports the logical circuit size. This is the entry
/// point a public-input decode exporter would use (qp-plonky2 formal/PLAN.md
/// Step 8): the wrapper's constraints, copy constraints and PI registration are
/// all present, while the leaf verifiers (trusted, `Plonky2Bridge.proof_sound`) are not.
#[test]
fn wrapper_only_n2_builds_without_verifiers() {
    let _ = env_logger::builder().is_test(true).try_init();
    let leaf = build_fake_leaf_circuit().0;
    let shape = PrivateBatchShape::new(2, 2);
    let mut builder = CircuitBuilder::<F, D>::new(wormhole_private_batch_circuit_config());

    let leaf_proofs = (0..shape.num_leaf_proofs)
        .map(|_| builder.add_virtual_proof_with_pis(&leaf.common))
        .collect();
    let mut targets = PrivateBatchCircuitTargets::allocate(&mut builder, leaf_proofs, shape);
    let gates_before = builder.num_gates();
    targets.nullifier_permutation_switches =
        super::build_private_batch_constraints(&mut builder, &targets);

    println!(
        "wrapper-only {shape:?}: gates={} (before wrapper: {gates_before}) pis={} switches={}",
        builder.num_gates(),
        builder.num_public_inputs(),
        targets.nullifier_permutation_switches.len(),
    );
    assert_eq!(
        builder.num_public_inputs(),
        aggregated_output::pi_len(shape)
    );
    assert_eq!(targets.nullifier_permutation_switches.len(), 1);

    let data = builder.build::<C>();
    println!(
        "built: degree={} gate types={:?} pis={}",
        data.common.degree(),
        data.common
            .gates
            .iter()
            .map(|g| g.0.id())
            .collect::<Vec<_>>(),
        data.prover_only.public_inputs.len(),
    );
}

/// Records the `n = n_leaf` wrapper's gadget calls and constraint system for the Lean
/// constraint exporter (`qp-plonky2/constraint-exporter`, PLAN.md Steps 8c and 8e) and checks
/// the trace `formal/traces/private_batch_wrapper_n{n_leaf}.json` is current. Regenerate with
/// `UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-aggregator --lib private_batch_wrapper_n`.
///
/// The traced shape uses `num_exit_slots == num_leaf_proofs`.
fn check_private_batch_wrapper_trace(n_leaf: usize) {
    use zk_circuits_common::formal_trace::{Trace, TracingBuilder};

    let leaf = build_fake_leaf_circuit().0;
    let shape = PrivateBatchShape::new(n_leaf, n_leaf);
    let mut tracing = TracingBuilder::new(wormhole_private_batch_circuit_config());

    // Where production runs `add_recursive_verifiers` under the leaf verifier key.
    let leaf_proofs: Vec<_> = (0..n_leaf)
        .map(|_| {
            let proof = tracing.inner.add_virtual_proof_with_pis(&leaf.common);
            tracing.verify_proof("leaf_circuit", &proof);
            proof
        })
        .collect();
    let rows_before = tracing.inner.num_gates();
    let mut targets = PrivateBatchCircuitTargets::allocate(&mut tracing, leaf_proofs, shape);
    targets.nullifier_permutation_switches =
        super::build_private_batch_constraints(&mut tracing, &targets);
    assert_eq!(
        rows_before, 0,
        "wrapper rows must start at 0 for the exporter"
    );

    let mut named = Vec::new();
    for (i, proof) in targets.leaf_proofs.iter().enumerate() {
        named.push((format!("leaf_pis_{i}"), proof.public_inputs.clone()));
    }
    named.push(("volume_fee_bps".to_string(), vec![targets.volume_fee_bps]));
    for (i, slot) in targets.exit_slots.iter().enumerate() {
        named.push((format!("exit_amount_{i}"), vec![slot.amount]));
        named.push((format!("exit_account_{i}"), slot.exit_account.to_vec()));
    }
    for (i, pre) in targets.dummy_nullifier_pre_images.iter().enumerate() {
        named.push((format!("dummy_pre_image_{i}"), pre.to_vec()));
    }
    named.push((
        "switches".to_string(),
        targets
            .nullifier_permutation_switches
            .iter()
            .map(|b| b.target)
            .collect(),
    ));
    let name = format!("private_batch_wrapper_n{n_leaf}");
    let trace = tracing.trace(&name, named);
    let json = trace.to_json();
    let round_trip = Trace::from_json(&json).expect("trace round-trips");
    assert_eq!(round_trip.to_json(), json);
    println!(
        "wrapper trace n={n_leaf}: rows={} copies={} calls={}",
        trace.rows.len(),
        trace.copies.len(),
        trace.calls.len()
    );

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../formal/traces/{name}.json"));
    if std::env::var_os("UPDATE_FORMAL_TRACE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &json).unwrap();
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        checked_in == json,
        "formal/traces/{name}.json is stale; regenerate with \
         UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-aggregator --lib \
         private_batch_wrapper_n"
    );
}

#[test]
fn private_batch_wrapper_n2_trace_is_current() {
    check_private_batch_wrapper_trace(2);
}

#[test]
fn private_batch_wrapper_n4_trace_is_current() {
    check_private_batch_wrapper_trace(4);
}
