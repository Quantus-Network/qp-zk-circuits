use std::collections::BTreeMap;

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
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierOnlyCircuitData,
        },
        config::Hasher,
        proof::ProofWithPublicInputs,
    },
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};

use crate::private_batch::{
    circuit::{
        circuit_logic::{PrivateBatchCircuit, PrivateBatchCircuitTargets},
        constants::{
            aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START,
            EXIT_2_START, INPUT_AMOUNT_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START,
            OUTPUT_AMOUNT_2_START, VOLUME_FEE_BPS_START,
        },
    },
    prover::witness::fill_private_batch_witness,
};

const TEST_ASSET_ID_U64: u64 = 0;
const TEST_VOLUME_FEE_BPS: u64 = 10; // 0.1% = 10 bps

// ---------------- Root PI header layout (private-batch aggregation output) ----------------
// [ num_exit_slots(1), asset_id(1), volume_fee_bps(1), block_hash(4), block_number(1), ... ]
const ROOT_NUM_EXIT_SLOTS_IDX: usize = 0;
const ROOT_ASSET_ID_IDX: usize = 1;
const ROOT_VOLUME_FEE_BPS_IDX: usize = 2;
const ROOT_BLOCK_HASH_START: usize = 3;
const ROOT_BLOCK_NUMBER_IDX: usize = 7;
const ROOT_HEADER_LEN: usize = 8;

// ---------------- Circuit helpers ----------------

use test_helpers::fake_leaf::{
    build_fake_leaf_circuit, prove_fake_leaf, prove_fake_leaf_standalone,
};

/// Build and prove the private-batch aggregation circuit using the split witness-filler path.
fn aggregate_proofs_private_batch(
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    leaf_common: CommonCircuitData<F, D>,
    leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
    dummy_nullifier_pre_images: Vec<[F; 4]>,
) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
    let nullifier_permutation: Vec<usize> = (0..leaf_proofs.len()).collect();
    aggregate_proofs_private_batch_with_permutation(
        leaf_proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
        nullifier_permutation,
    )
}

fn aggregate_proofs_private_batch_with_permutation(
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    leaf_common: CommonCircuitData<F, D>,
    leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
    dummy_nullifier_pre_images: Vec<[F; 4]>,
    nullifier_permutation: Vec<usize>,
) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
    let n_leaf = leaf_proofs.len();
    assert!(n_leaf > 0, "need at least one leaf proof");
    assert_eq!(
        dummy_nullifier_pre_images.len(),
        n_leaf,
        "dummy_nullifier_pre_images must have one entry per leaf slot"
    );
    assert_eq!(nullifier_permutation.len(), n_leaf);

    let agg_config = wormhole_private_batch_circuit_config();
    // SECURITY: leaf_verifier_only is now baked in at build time
    let agg_circuit = PrivateBatchCircuit::new(
        agg_config.clone(),
        &leaf_common,
        &leaf_verifier_only,
        n_leaf,
    )?;
    let targets = agg_circuit.targets();
    let prover_data = agg_circuit.build_prover();

    let mut pw = PartialWitness::new();
    // NOTE: leaf_verifier_only is no longer passed here - it's baked in as constants
    fill_private_batch_witness(
        &mut pw,
        &targets,
        &leaf_proofs,
        &dummy_nullifier_pre_images,
        &nullifier_permutation,
    )?;

    let agg_proof = prover_data.prove(pw)?;

    // Build verifier data from the same config/leaf common so we can verify the result.
    // NOTE: Must use the same leaf_verifier_only to get matching circuit digest
    let verifier_data =
        PrivateBatchCircuit::new(agg_config, &leaf_common, &leaf_verifier_only, n_leaf)?
            .build_verifier();

    Ok((agg_proof, verifier_data))
}

fn deterministic_dummy_nullifier_pre_images(n: usize) -> Vec<[F; 4]> {
    let mut rng = StdRng::from_seed([77u8; 32]);
    (0..n)
        .map(|_| {
            [
                F::from_canonical_u64(rng.gen::<u32>() as u64),
                F::from_canonical_u64(rng.gen::<u32>() as u64),
                F::from_canonical_u64(rng.gen::<u32>() as u64),
                F::from_canonical_u64(rng.gen::<u32>() as u64),
            ]
        })
        .collect()
}

fn prove_private_batch_with_data(
    data: &CircuitData<F, C, D>,
    targets: &PrivateBatchCircuitTargets,
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    fill_private_batch_witness(
        &mut pw,
        targets,
        proofs,
        &deterministic_dummy_nullifier_pre_images(proofs.len()),
        &(0..proofs.len()).collect::<Vec<_>>(),
    )?;
    data.prove(pw)
}

fn hash_dummy_nullifier_pre_image_native(pre_image: [F; 4]) -> [F; 4] {
    let inner_hash = Poseidon2Hash::hash_no_pad(&pre_image).elements;
    Poseidon2Hash::hash_no_pad(&inner_hash).elements
}

/// Read the nullifier region (`n_leaf` entries of 4 felts) from aggregated PIs.
fn nullifier_region(pis: &[F], n_leaf: usize) -> Vec<[F; 4]> {
    let start = ROOT_HEADER_LEN + n_leaf * 2 * aggregated_output::EXIT_SLOT_LEN;
    (0..n_leaf)
        .map(|i| core::array::from_fn(|j| pis[start + i * 4 + j]))
        .collect()
}

// ---------------- Packing helpers ----------------

#[inline]
fn limbs4_u64_to_felts(l: [u64; 4]) -> [F; 4] {
    [
        F::from_canonical_u64(l[0]),
        F::from_canonical_u64(l[1]),
        F::from_canonical_u64(l[2]),
        F::from_canonical_u64(l[3]),
    ]
}

#[inline]
fn limbs8_u64_to_felts(l: [u64; 8]) -> [F; 8] {
    core::array::from_fn(|i| F::from_canonical_u64(l[i]))
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn make_pi_from_felts(
    asset_id: F,
    output_amount_1: F,
    output_amount_2: F,
    volume_fee_bps: F,
    nullifier: [F; 4],
    exit_1: [F; 8],
    exit_2: [F; 8],
    block_hash: [F; 4],
    block_number: F,
) -> [F; LEAF_PI_LEN] {
    let mut out = [F::ZERO; LEAF_PI_LEN];
    out[ASSET_ID_START] = asset_id;
    out[OUTPUT_AMOUNT_1_START] = output_amount_1;
    out[OUTPUT_AMOUNT_2_START] = output_amount_2;
    out[VOLUME_FEE_BPS_START] = volume_fee_bps;
    out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
    out[EXIT_1_START..EXIT_1_START + 8].copy_from_slice(&exit_1);
    out[EXIT_2_START..EXIT_2_START + 8].copy_from_slice(&exit_2);
    out[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&block_hash);
    out[BLOCK_NUMBER_START] = block_number;
    let output = output_amount_1
        .to_canonical_u64()
        .saturating_add(output_amount_2.to_canonical_u64());
    let fee = volume_fee_bps.to_canonical_u64();
    let minimum_input = if output == 0 || fee >= 10_000 {
        0
    } else {
        output.saturating_mul(10_000).div_ceil(10_000 - fee)
    };
    out[INPUT_AMOUNT_START] = F::from_canonical_u64(minimum_input);
    out
}

fn prove_amount_batch(
    leaf_data: &CircuitData<F, C, D>,
    leaf_targets: &[Target; LEAF_PI_LEN],
    inputs: &[u64],
    outputs: &[(u64, u64)],
    fee_bps: u64,
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(inputs.len(), outputs.len());
    inputs
        .iter()
        .zip(outputs)
        .enumerate()
        .map(|(i, (&input, &(output_1, output_2)))| {
            let exit_2 = if output_2 == 0 {
                [F::ZERO; 8]
            } else {
                core::array::from_fn(|j| F::from_canonical_usize(1_000 + i * 8 + j))
            };
            let mut pis = make_pi_from_felts(
                F::ZERO,
                F::from_canonical_u64(output_1),
                F::from_canonical_u64(output_2),
                F::from_canonical_u64(fee_bps),
                limbs4_u64_to_felts(NULLIFIERS[i]),
                limbs8_u64_to_felts(EXIT_ACCOUNTS[i]),
                exit_2,
                limbs4_u64_to_felts(BLOCK_HASHES[0]),
                F::from_canonical_u64(42),
            );
            pis[INPUT_AMOUNT_START] = F::from_canonical_u64(input);
            prove_fake_leaf(leaf_data, leaf_targets, pis)
        })
        .collect()
}

// ---------------- Hardcoded 64-bit-limb digests ----------------
// Exit accounts use 8 felts (32-bit values) for collision-resistant encoding

const EXIT_ACCOUNTS: [[u64; 8]; 8] = [
    [
        0x1111_0001,
        0x0000_0001,
        0x1111_0002,
        0x0000_0002,
        0x1111_0003,
        0x0000_0003,
        0x1111_0004,
        0x0000_0004,
    ],
    [
        0x2222_0001,
        0x0000_0001,
        0x2222_0002,
        0x0000_0002,
        0x2222_0003,
        0x0000_0003,
        0x2222_0004,
        0x0000_0004,
    ],
    [
        0x3333_0001,
        0x0000_0001,
        0x3333_0002,
        0x0000_0002,
        0x3333_0003,
        0x0000_0003,
        0x3333_0004,
        0x0000_0004,
    ],
    [
        0x4444_0001,
        0x0000_0001,
        0x4444_0002,
        0x0000_0002,
        0x4444_0003,
        0x0000_0003,
        0x4444_0004,
        0x0000_0004,
    ],
    [
        0x5555_0001,
        0x0000_0001,
        0x5555_0002,
        0x0000_0002,
        0x5555_0003,
        0x0000_0003,
        0x5555_0004,
        0x0000_0004,
    ],
    [
        0x6666_0001,
        0x0000_0001,
        0x6666_0002,
        0x0000_0002,
        0x6666_0003,
        0x0000_0003,
        0x6666_0004,
        0x0000_0004,
    ],
    [
        0x7777_0001,
        0x0000_0001,
        0x7777_0002,
        0x0000_0002,
        0x7777_0003,
        0x0000_0003,
        0x7777_0004,
        0x0000_0004,
    ],
    [
        0x8888_0001,
        0x0000_0001,
        0x8888_0002,
        0x0000_0002,
        0x8888_0003,
        0x0000_0003,
        0x8888_0004,
        0x0000_0004,
    ],
];

const BLOCK_HASHES: [[u64; 4]; 8] = [
    [
        0xAAAA_0001_0000_0001,
        0xAAAA_0001_0000_0002,
        0xAAAA_0001_0000_0003,
        0xAAAA_0001_0000_0004,
    ],
    [
        0xBBBB_0001_0000_0001,
        0xBBBB_0001_0000_0002,
        0xBBBB_0001_0000_0003,
        0xBBBB_0001_0000_0004,
    ],
    [
        0xCCCC_0001_0000_0001,
        0xCCCC_0001_0000_0002,
        0xCCCC_0001_0000_0003,
        0xCCCC_0001_0000_0004,
    ],
    [
        0xDDDD_0001_0000_0001,
        0xDDDD_0001_0000_0002,
        0xDDDD_0001_0000_0003,
        0xDDDD_0001_0000_0004,
    ],
    [
        0xEEEE_0001_0000_0001,
        0xEEEE_0001_0000_0002,
        0xEEEE_0001_0000_0003,
        0xEEEE_0001_0000_0004,
    ],
    [
        0xFFFF_0001_0000_0001,
        0xFFFF_0001_0000_0002,
        0xFFFF_0001_0000_0003,
        0xFFFF_0001_0000_0004,
    ],
    [
        0xABCD_0001_0000_0001,
        0xABCD_0001_0000_0002,
        0xABCD_0001_0000_0003,
        0xABCD_0001_0000_0004,
    ],
    [
        0x1234_0001_0000_0001,
        0x1234_0001_0000_0002,
        0x1234_0001_0000_0003,
        0x1234_0001_0000_0004,
    ],
];

const NULLIFIERS: [[u64; 4]; 8] = [
    [
        0x90A0_0001_0000_0001,
        0x90A0_0001_0000_0002,
        0x90A0_0001_0000_0003,
        0x90A0_0001_0000_0004,
    ],
    [
        0x80B0_0001_0000_0001,
        0x80B0_0001_0000_0002,
        0x80B0_0001_0000_0003,
        0x80B0_0001_0000_0004,
    ],
    [
        0x70C0_0001_0000_0001,
        0x70C0_0001_0000_0002,
        0x70C0_0001_0000_0003,
        0x70C0_0001_0000_0004,
    ],
    [
        0x60D0_0001_0000_0001,
        0x60D0_0001_0000_0002,
        0x60D0_0001_0000_0003,
        0x60D0_0001_0000_0004,
    ],
    [
        0x50E0_0001_0000_0001,
        0x50E0_0001_0000_0002,
        0x50E0_0001_0000_0003,
        0x50E0_0001_0000_0004,
    ],
    [
        0x40F0_0001_0000_0001,
        0x40F0_0001_0000_0002,
        0x40F0_0001_0000_0003,
        0x40F0_0001_0000_0004,
    ],
    [
        0x30A1_0001_0000_0001,
        0x30A1_0001_0000_0002,
        0x30A1_0001_0000_0003,
        0x30A1_0001_0000_0004,
    ],
    [
        0x20B2_0001_0000_0001,
        0x20B2_0001_0000_0002,
        0x20B2_0001_0000_0003,
        0x20B2_0001_0000_0004,
    ],
];

#[test]
fn aggregate_fee_regressions() {
    const N_LEAF: usize = 7;

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let aggregate = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        N_LEAF,
    )
    .unwrap();
    let aggregate_targets = aggregate.targets();
    let aggregate_data = aggregate.build_circuit();

    let prove_case =
        |inputs: &[u64], outputs: &[(u64, u64)], fee_bps: u64, dummy_input: u64| -> Result<_> {
            let mut proofs =
                prove_amount_batch(&leaf_data, &leaf_targets, inputs, outputs, fee_bps);
            for (i, nullifier) in NULLIFIERS
                .iter()
                .enumerate()
                .take(N_LEAF)
                .skip(inputs.len())
            {
                let mut pis = make_pi_from_felts(
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::from_canonical_u64(fee_bps),
                    limbs4_u64_to_felts(*nullifier),
                    [F::ZERO; 8],
                    [F::ZERO; 8],
                    [F::ZERO; 4],
                    F::ZERO,
                );
                if i == inputs.len() {
                    pis[INPUT_AMOUNT_START] = F::from_canonical_u64(dummy_input);
                }
                proofs.push(prove_fake_leaf(&leaf_data, &leaf_targets, pis));
            }

            prove_private_batch_with_data(&aggregate_data, &aggregate_targets, &proofs)
        };

    assert!(
        prove_case(
            &[100, 1, 1, 1, 1],
            &[(20, 0), (20, 0), (20, 0), (20, 0), (23, 0)],
            4,
            0,
        )
        .is_ok(),
        "103q out from 104q in must pay the 1q segment fee"
    );
    assert!(
        prove_case(
            &[100, 1, 1, 1, 1],
            &[(20, 0), (20, 0), (20, 0), (20, 0), (24, 0)],
            4,
            0,
        )
        .is_err(),
        "104q out from 104q in must not bypass the fee"
    );
    assert!(
        prove_case(&[2_500], &[(2_499, 0)], 4, 0).is_ok(),
        "2499q out requires exactly 2500q in at 4 bps"
    );
    assert!(
        prove_case(&[2_499], &[(2_499, 0)], 4, 0).is_err(),
        "a one-real-leaf segment must still pay its ceiling fee"
    );
    assert!(
        prove_case(
            &[2, 2, 2, 2, 2, 2, 2],
            &[(2, 0), (2, 0), (2, 0), (2, 0), (2, 0), (2, 0), (1, 0)],
            4,
            0,
        )
        .is_ok(),
        "13q out from 14q in must be valid with one aggregate fee quantum"
    );
    assert!(
        prove_case(&[1], &[(1, 0)], 4, u32::MAX as u64).is_err(),
        "dummy input value must not subsidize a real exit"
    );
    assert!(
        prove_case(&[100], &[(100, 0)], 0, 0).is_ok()
            && prove_case(&[99], &[(100, 0)], 0, 0).is_err(),
        "zero-fee batches must enforce total output <= total input"
    );
    assert!(
        prove_case(&[10_000], &[(1, 0)], 9_999, 0).is_ok()
            && prove_case(&[9_999], &[(1, 0)], 9_999, 0).is_err(),
        "9999 bps must use a denominator of one"
    );
    assert!(
        prove_case(&[0], &[(0, 0)], 10_000, 0).is_ok()
            && prove_case(&[u32::MAX as u64], &[(1, 0)], 10_000, 0).is_err(),
        "10000 bps must allow only zero aggregate output"
    );
    assert!(
        prove_case(&[2_500], &[(1_249, 1_250)], 4, 0).is_ok()
            && prove_case(&[2_499], &[(1_249, 1_250)], 4, 0).is_err(),
        "both output slots must contribute to the aggregate fee boundary"
    );

    let max = u32::MAX as u64;
    assert!(
        prove_case(&[max; N_LEAF], &[(max - 2_000_000, 0); N_LEAF], 4, 0,).is_ok(),
        "large valid totals must not wrap the field or the 52-bit difference check"
    );
    assert!(
        prove_case(&[0; N_LEAF], &[(max, 0); N_LEAF], 0, 0).is_err(),
        "a large negative integer fee difference must not pass through field wraparound"
    );
    assert!(
        prove_case(&[1], &[(0, 0)], 10_001, 0).is_err(),
        "the aggregate fee rate must remain bounded by 10000 bps"
    );
}

#[test]
fn private_batch_masking_uniqueness_and_privacy_regressions() {
    const N_LEAF: usize = 2;

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let aggregate = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        N_LEAF,
    )
    .unwrap();
    let aggregate_targets = aggregate.targets();
    let aggregate_data = aggregate.build_circuit();
    let common_block_hash = limbs4_u64_to_felts(BLOCK_HASHES[0]);

    let prove_pis = |pis_list: Vec<[F; LEAF_PI_LEN]>| {
        let proofs = pis_list
            .into_iter()
            .map(|pis| prove_fake_leaf(&leaf_data, &leaf_targets, pis))
            .collect::<Vec<_>>();
        prove_private_batch_with_data(&aggregate_data, &aggregate_targets, &proofs)
    };

    let make_real_pi = |input: u64, output: u64, fee_bps: u64, nullifier: [F; 4], exit: [F; 8]| {
        let mut pis = make_pi_from_felts(
            F::ZERO,
            F::from_canonical_u64(output),
            F::ZERO,
            F::from_canonical_u64(fee_bps),
            nullifier,
            exit,
            [F::ZERO; 8],
            common_block_hash,
            F::from_canonical_u64(42),
        );
        pis[INPUT_AMOUNT_START] = F::from_canonical_u64(input);
        pis
    };

    let duplicate_nullifier = limbs4_u64_to_felts(NULLIFIERS[0]);
    assert!(
        prove_pis(vec![
            make_real_pi(
                1,
                1,
                0,
                duplicate_nullifier,
                limbs8_u64_to_felts(EXIT_ACCOUNTS[0]),
            ),
            make_real_pi(
                1,
                1,
                0,
                duplicate_nullifier,
                limbs8_u64_to_felts(EXIT_ACCOUNTS[1]),
            ),
        ])
        .is_err(),
        "the circuit must reject duplicate real nullifiers without relying on prover preflight"
    );

    let mut poisoned_dummy = make_pi_from_felts(
        F::ZERO,
        F::from_canonical_u32(u32::MAX),
        F::from_canonical_u32(u32::MAX),
        F::from_canonical_u64(9_999),
        limbs4_u64_to_felts(NULLIFIERS[0]),
        limbs8_u64_to_felts(EXIT_ACCOUNTS[0]),
        limbs8_u64_to_felts(EXIT_ACCOUNTS[1]),
        [F::ZERO; 4],
        F::ZERO,
    );
    poisoned_dummy[INPUT_AMOUNT_START] = F::from_canonical_u32(u32::MAX);
    let masked = prove_pis(vec![
        poisoned_dummy,
        make_real_pi(
            10_000,
            9_996,
            4,
            limbs4_u64_to_felts(NULLIFIERS[1]),
            limbs8_u64_to_felts(EXIT_ACCOUNTS[2]),
        ),
    ])
    .expect("leading dummy values must be masked");
    assert_eq!(
        masked.public_inputs[ROOT_VOLUME_FEE_BPS_IDX].to_canonical_u64(),
        4,
        "the fee reference must come from the first real leaf"
    );
    assert!(
        masked.public_inputs
            [ROOT_HEADER_LEN..ROOT_HEADER_LEN + 2 * aggregated_output::EXIT_SLOT_LEN]
            .iter()
            .all(|value| *value == F::ZERO),
        "dummy outputs and exit accounts must not reach aggregate public inputs"
    );

    let public_inputs_for = |inputs: [u64; N_LEAF]| {
        prove_pis(vec![
            make_real_pi(
                inputs[0],
                20,
                0,
                limbs4_u64_to_felts(NULLIFIERS[0]),
                limbs8_u64_to_felts(EXIT_ACCOUNTS[0]),
            ),
            make_real_pi(
                inputs[1],
                30,
                0,
                limbs4_u64_to_felts(NULLIFIERS[1]),
                limbs8_u64_to_felts(EXIT_ACCOUNTS[1]),
            ),
        ])
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
#[ignore = "slow: builds and proves the maximum 64-leaf recursive circuit"]
fn maximum_width_private_batch_fee_does_not_wrap() {
    const N_LEAF: usize = 64;

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let block_hash = limbs4_u64_to_felts(BLOCK_HASHES[0]);
    let max = u32::MAX as u64;
    let proofs = (0..N_LEAF)
        .map(|i| {
            let nullifier = core::array::from_fn(|j| F::from_canonical_usize(1 + i * 4 + j));
            let exit = core::array::from_fn(|j| F::from_canonical_usize(1 + i * 8 + j));
            let mut pis = make_pi_from_felts(
                F::ZERO,
                F::from_canonical_u64(max - 2_000_000),
                F::ZERO,
                F::from_canonical_u64(4),
                nullifier,
                exit,
                [F::ZERO; 8],
                block_hash,
                F::from_canonical_u64(42),
            );
            pis[INPUT_AMOUNT_START] = F::from_canonical_u64(max);
            prove_fake_leaf(&leaf_data, &leaf_targets, pis)
        })
        .collect::<Vec<_>>();

    let aggregate = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        N_LEAF,
    )
    .unwrap();
    let targets = aggregate.targets();
    let data = aggregate.build_circuit();
    let proof = prove_private_batch_with_data(&data, &targets, &proofs).unwrap();
    data.verify(proof).unwrap();
}

#[test]
fn recursive_aggregation_tree() {
    let mut rng = StdRng::from_seed([41u8; 32]);

    let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
    let output2_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);

    let output1_felts: [F; 8] =
        core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));
    let output2_felts: [F; 8] =
        core::array::from_fn(|i| F::from_canonical_u64(output2_vals_u32[i] as u64));

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    // All real proofs must be from the same block
    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);

    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
    for i in 0..8 {
        pis_list.push(make_pi_from_felts(
            asset_id,
            output1_felts[i],
            output2_felts[i],
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            exits_felts[(i + 1) % 8],
            common_block_hash,
            common_block_number,
        ));
    }

    let leaves = pis_list
        .clone()
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();

    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();

    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let (root_proof, root_verifier) = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
    )
    .unwrap();

    // ---------------------------
    // Reference aggregation OFF-CIRCUIT
    // ---------------------------
    let n_leaf = pis_list.len();
    assert_eq!(n_leaf, 8);

    let mut exit_sums: BTreeMap<[F; 4], F> = BTreeMap::new();
    for (i, pis) in pis_list.iter().enumerate() {
        let exit_1: [F; 4] = core::array::from_fn(|j| pis[EXIT_1_START + j]);
        let amount_1 = output1_felts[i];
        exit_sums
            .entry(exit_1)
            .and_modify(|s| *s += amount_1)
            .or_insert(amount_1);

        let exit_2: [F; 4] = core::array::from_fn(|j| pis[EXIT_2_START + j]);
        let amount_2 = output2_felts[i];
        exit_sums
            .entry(exit_2)
            .and_modify(|s| *s += amount_2)
            .or_insert(amount_2);
    }

    let block_hash_ref = common_block_hash;
    let block_num_ref = common_block_number;

    let mut nullifiers_ref: Vec<[F; 4]> = Vec::with_capacity(n_leaf);
    for pis in &pis_list {
        nullifiers_ref.push([
            pis[NULLIFIER_START],
            pis[NULLIFIER_START + 1],
            pis[NULLIFIER_START + 2],
            pis[NULLIFIER_START + 3],
        ]);
    }

    // ---------------------------
    // Parse aggregated PIs
    // ---------------------------
    let pis = &root_proof.public_inputs;
    let root_pi_len = n_leaf * LEAF_PI_LEN;
    assert_eq!(pis.len(), root_pi_len + ROOT_HEADER_LEN);

    let num_exit_slots_circuit = pis[ROOT_NUM_EXIT_SLOTS_IDX].to_canonical_u64() as usize;
    assert_eq!(num_exit_slots_circuit, n_leaf * 2);

    let asset_id_circuit = pis[ROOT_ASSET_ID_IDX];
    assert_eq!(asset_id_circuit, asset_id);

    let volume_fee_bps_circuit = pis[ROOT_VOLUME_FEE_BPS_IDX];
    assert_eq!(volume_fee_bps_circuit, volume_fee_bps);

    let block_hash_circuit: [F; 4] = [
        pis[ROOT_BLOCK_HASH_START],
        pis[ROOT_BLOCK_HASH_START + 1],
        pis[ROOT_BLOCK_HASH_START + 2],
        pis[ROOT_BLOCK_HASH_START + 3],
    ];
    let block_num_circuit = pis[ROOT_BLOCK_NUMBER_IDX];
    assert_eq!(block_hash_circuit, block_hash_ref);
    assert_eq!(block_num_circuit, block_num_ref);

    let mut idx = ROOT_HEADER_LEN;

    // Exit slots region: 2*N slots, each [sum(1), exit(4)]
    let mut exit_sums_from_circuit: BTreeMap<[F; 4], F> = BTreeMap::new();
    for _ in 0..(n_leaf * 2) {
        let sum_circuit = pis[idx];
        idx += 1;

        let exit_key_circuit: [F; 4] = core::array::from_fn(|j| pis[idx + j]);
        idx += 4;

        if sum_circuit != F::ZERO {
            exit_sums_from_circuit
                .entry(exit_key_circuit)
                .or_insert(sum_circuit);
        }
    }

    // Convert to u64-based keys for reliable comparison
    // (BTreeMap with [F; 4] keys can be unreliable due to Ord impl)
    let exit_sums_u64: std::collections::HashMap<[u64; 4], u64> = exit_sums
        .iter()
        .map(|(k, v)| {
            let k_u64: [u64; 4] = core::array::from_fn(|i| k[i].to_canonical_u64());
            (k_u64, v.to_canonical_u64())
        })
        .collect();

    let exit_sums_from_circuit_u64: std::collections::HashMap<[u64; 4], u64> =
        exit_sums_from_circuit
            .iter()
            .map(|(k, v)| {
                let k_u64: [u64; 4] = core::array::from_fn(|i| k[i].to_canonical_u64());
                (k_u64, v.to_canonical_u64())
            })
            .collect();

    assert_eq!(
        exit_sums_u64.len(),
        exit_sums_from_circuit_u64.len(),
        "exit_sums size mismatch"
    );

    for (exit_key_u64, sum_ref_u64) in &exit_sums_u64 {
        let sum_from_circuit_u64 =
            exit_sums_from_circuit_u64
                .get(exit_key_u64)
                .unwrap_or_else(|| {
                    panic!(
                        "exit_key {:?} not found in circuit output (sum_ref={})",
                        exit_key_u64, sum_ref_u64
                    )
                });
        assert_eq!(
            *sum_from_circuit_u64, *sum_ref_u64,
            "sum mismatch for exit {:?}",
            exit_key_u64
        );
    }

    // The test helper witnesses the identity permutation.
    let expected_nullifiers = nullifiers_ref;
    for (region_idx, nullifier_expected) in expected_nullifiers.iter().enumerate() {
        let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
        idx += 4;

        assert_eq!(
            got, *nullifier_expected,
            "nullifier mismatch at region index {region_idx}"
        );
    }

    // Padding zeros
    while idx < pis.len() {
        assert_eq!(pis[idx], F::ZERO, "expected zero padding at index {idx}");
        idx += 1;
    }

    // Verify final proof
    root_verifier.verify(root_proof).unwrap();
}

#[test]
fn recursive_aggregation_tree_different_blocks_fails() {
    let mut rng = StdRng::from_seed([42u8; 32]);

    let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
    let output1_felts: [F; 8] =
        core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
    for i in 0..8 {
        pis_list.push(make_pi_from_felts(
            asset_id,
            output1_felts[i],
            F::ZERO,
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            [F::ZERO; 8],
            block_hashes_felts[i], // different block hash per proof -> should fail
            block_numbers[i],      // different block number per proof -> should fail
        ));
    }

    let leaves = pis_list
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();
    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let res = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
    );

    assert!(
        res.is_err(),
        "expected failure because proofs are from different blocks"
    );
}

#[test]
fn recursive_aggregation_tree_mismatched_asset_id_fails() {
    let asset_a = F::from_canonical_u64(7);
    let asset_b = F::from_canonical_u64(9);

    let output_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
    for i in 0..8 {
        let asset_id = if i == 3 { asset_b } else { asset_a };
        pis_list.push(make_pi_from_felts(
            asset_id,
            output_felts[i],
            F::ZERO,
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            [F::ZERO; 8],
            block_hashes_felts[i],
            block_numbers[i],
        ));
    }

    let leaves = pis_list
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();
    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let res = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
    );

    assert!(res.is_err(), "expected failure due to mismatched asset IDs");
}

#[test]
fn recursive_aggregation_tree_with_dummy_proofs() {
    // 2 real proofs + 6 dummy proofs (block_hash = 0 sentinel)
    let mut rng = StdRng::from_seed([99u8; 32]);

    let output_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
    let output_felts: [F; 8] =
        core::array::from_fn(|i| F::from_canonical_u64(output_vals_u32[i] as u64));

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let num_real_proofs = 2usize;

    // All real proofs share the same block
    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);

    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);

    // Real proofs
    for i in 0..num_real_proofs {
        pis_list.push(make_pi_from_felts(
            asset_id,
            output_felts[i],
            F::ZERO,
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            [F::ZERO; 8],
            common_block_hash,
            common_block_number,
        ));
    }

    // Dummy proofs: zero block hash + zero outputs + zero exits
    let dummy_exit = [F::ZERO; 8];
    let dummy_block_hash = [F::ZERO; 4];
    for nullifier in nullifiers_felts.iter().skip(num_real_proofs) {
        pis_list.push(make_pi_from_felts(
            asset_id,
            F::ZERO,
            F::ZERO,
            volume_fee_bps,
            *nullifier, // private-batch replaces dummy nullifiers with hashes of provided preimages
            dummy_exit,
            dummy_exit,
            dummy_block_hash,
            F::ZERO,
        ));
    }

    let leaves = pis_list
        .clone()
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();

    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let (root_proof, root_verifier) = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images.clone(),
    )
    .unwrap();

    root_verifier.verify(root_proof.clone()).unwrap();

    let pis = &root_proof.public_inputs;

    // Root header should reference the real block
    let block_hash_circuit: [F; 4] = [
        pis[ROOT_BLOCK_HASH_START],
        pis[ROOT_BLOCK_HASH_START + 1],
        pis[ROOT_BLOCK_HASH_START + 2],
        pis[ROOT_BLOCK_HASH_START + 3],
    ];
    assert_eq!(block_hash_circuit, common_block_hash);

    let block_num_circuit = pis[ROOT_BLOCK_NUMBER_IDX];
    assert_eq!(block_num_circuit, common_block_number);

    // The test helper witnesses the identity permutation.
    let mut expected: Vec<[F; 4]> = nullifiers_felts[..num_real_proofs].to_vec();
    expected.extend(
        dummy_nullifier_pre_images
            .iter()
            .skip(num_real_proofs)
            .map(|p| hash_dummy_nullifier_pre_image_native(*p)),
    );
    assert_eq!(
        nullifier_region(pis, pis_list.len()),
        expected,
        "nullifier region must preserve real and dummy-replacement nullifiers"
    );

    println!(
        "Successfully aggregated {} real proofs + {} dummy proofs!",
        num_real_proofs,
        8 - num_real_proofs
    );
}

/// The leaf circuit leaves exit accounts unconstrained and its dummy
/// sentinel (`block_hash == 0 && amounts == 0`) does not cover them, so a
/// valid dummy leaf can carry attacker-chosen exit accounts. The wrapper
/// must mask dummy slots' exits to the canonical zero account in the
/// aggregated output, or a poisoned padding template marks every padded
/// slot as visibly dummy (audit finding: incomplete dummy sentinel).
#[test]
fn recursive_aggregation_masks_dummy_exit_accounts_to_zero() {
    const N_LEAF: usize = 4;

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);

    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
    let common_block_hash = block_hashes_felts[0];
    let real_amount = F::from_canonical_u64(1234);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(N_LEAF);
    // Slot 0: the one real proof.
    pis_list.push(make_pi_from_felts(
        asset_id,
        real_amount,
        F::ZERO,
        volume_fee_bps,
        nullifiers_felts[0],
        exits_felts[0],
        [F::ZERO; 8],
        common_block_hash,
        F::from_canonical_u64(42),
    ));
    // Slots 1..4: dummies (block_hash = 0, zero amounts) with
    // ATTACKER-CHOSEN nonzero exit accounts, as a poisoned template
    // could produce.
    for i in 1..N_LEAF {
        pis_list.push(make_pi_from_felts(
            asset_id,
            F::ZERO,
            F::ZERO,
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            exits_felts[i],
            [F::ZERO; 4],
            F::ZERO,
        ));
    }

    let leaves = pis_list
        .clone()
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();

    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let (root_proof, root_verifier) = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
    )
    .unwrap();
    root_verifier.verify(root_proof.clone()).unwrap();

    let pis = &root_proof.public_inputs;

    // Slots 2i / 2i+1 belong to proof i, so slots 2.. are the dummies'.
    // Every one of them must be fully zero — amount AND exit account —
    // regardless of the exit bytes the dummy leaves carried.
    for slot in 2..N_LEAF * 2 {
        let base = ROOT_HEADER_LEN + slot * aggregated_output::EXIT_SLOT_LEN;
        assert_eq!(pis[base], F::ZERO, "dummy slot {slot} must have zero sum");
        for j in 0..4 {
            assert_eq!(
                pis[base + 1 + j],
                F::ZERO,
                "dummy slot {slot} must expose the canonical zero exit account, \
                 not the template's exit bytes"
            );
        }
    }

    // The real proof's payout is untouched: slot 0 keeps its exit and sum.
    let base = ROOT_HEADER_LEN;
    assert_eq!(pis[base], real_amount, "real slot must keep its payout");
    for j in 0..4 {
        assert_eq!(
            pis[base + 1 + j],
            exits_felts[0][j],
            "real slot must keep its exit account"
        );
    }
}

/// Regression test: the circuit must accept the real proof in EVERY slot position. The
/// old circuit read its block reference from slot 0 and required the prover to pin a
/// real proof there, leaking that nullifier[0] was always real. The block reference is
/// now selected in-circuit from the first non-dummy slot, so any slot order (uniform
/// shuffle) must be satisfiable.
///
/// Runs the full flow (leaf proving, aggregation, root verification, public-input
/// checks) once per position of the real proof in a 4-leaf batch.
#[test]
fn recursive_aggregation_real_proof_in_every_slot_succeeds() {
    const N_LEAF: usize = 4;

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);
    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let dummy_exit = [F::ZERO; 8];
    let dummy_block_hash = [F::ZERO; 4];

    for real_slot in 0..N_LEAF {
        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(N_LEAF);

        for i in 0..N_LEAF {
            if i == real_slot {
                let real_amount = F::from_canonical_u64(500);
                pis_list.push(make_pi_from_felts(
                    asset_id,
                    real_amount,
                    F::ZERO,
                    volume_fee_bps,
                    nullifiers_felts[i],
                    exits_felts[i],
                    [F::ZERO; 8],
                    common_block_hash,
                    common_block_number,
                ));
            } else {
                pis_list.push(make_pi_from_felts(
                    asset_id,
                    F::ZERO,
                    F::ZERO,
                    volume_fee_bps,
                    nullifiers_felts[i],
                    dummy_exit,
                    dummy_exit,
                    dummy_block_hash,
                    F::ZERO,
                ));
            }
        }

        let leaves = pis_list
            .clone()
            .into_iter()
            .map(prove_fake_leaf_standalone)
            .collect::<Vec<_>>();
        let leaf_common = leaves[0].1.common.clone();
        let leaf_verifier_only = leaves[0].1.verifier_only.clone();
        let proofs = leaves
            .into_iter()
            .map(|(proof, _)| proof)
            .collect::<Vec<_>>();

        let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

        let (root_proof, root_verifier) = aggregate_proofs_private_batch(
            proofs,
            leaf_common,
            leaf_verifier_only,
            dummy_nullifier_pre_images.clone(),
        )
        .unwrap_or_else(|e| {
            panic!("aggregation with real proof in slot {real_slot} must be satisfiable: {e}")
        });

        root_verifier.verify(root_proof.clone()).unwrap();

        let pis = &root_proof.public_inputs;

        // Header must reference the real block regardless of which slot holds it.
        let block_hash_circuit: [F; 4] = [
            pis[ROOT_BLOCK_HASH_START],
            pis[ROOT_BLOCK_HASH_START + 1],
            pis[ROOT_BLOCK_HASH_START + 2],
            pis[ROOT_BLOCK_HASH_START + 3],
        ];
        assert_eq!(
            block_hash_circuit, common_block_hash,
            "block reference must come from the real slot {real_slot}"
        );
        assert_eq!(pis[ROOT_BLOCK_NUMBER_IDX], common_block_number);

        // The identity permutation forwards the real slot's nullifier unchanged
        // and replaces every dummy slot with H(H(pre_image)).
        let expected: Vec<[F; 4]> = (0..N_LEAF)
            .map(|i| {
                if i == real_slot {
                    nullifiers_felts[i]
                } else {
                    hash_dummy_nullifier_pre_image_native(dummy_nullifier_pre_images[i])
                }
            })
            .collect();
        assert_eq!(
            nullifier_region(pis, N_LEAF),
            expected,
            "nullifier region mismatch with real proof in slot {real_slot}"
        );
    }
}

#[test]
fn recursive_aggregation_tree_all_dummy_proofs() {
    // All 8 proofs are dummy (block_hash = 0 sentinel)
    // This tests that the circuit accepts an all-dummy batch
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let dummy_exit = [F::ZERO; 8];
    let dummy_block_hash = [F::ZERO; 4];

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
    for nullifier in &nullifiers_felts {
        pis_list.push(make_pi_from_felts(
            asset_id,
            F::ZERO,
            F::ZERO,
            volume_fee_bps,
            *nullifier,
            dummy_exit,
            dummy_exit,
            dummy_block_hash,
            F::ZERO,
        ));
    }

    let leaves = pis_list
        .clone()
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();

    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let (root_proof, root_verifier) = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images.clone(),
    )
    .unwrap();

    root_verifier.verify(root_proof.clone()).unwrap();

    let pis = &root_proof.public_inputs;

    // Block hash should be zero (all dummy)
    let block_hash_circuit: [F; 4] = [
        pis[ROOT_BLOCK_HASH_START],
        pis[ROOT_BLOCK_HASH_START + 1],
        pis[ROOT_BLOCK_HASH_START + 2],
        pis[ROOT_BLOCK_HASH_START + 3],
    ];
    assert_eq!(
        block_hash_circuit,
        [F::ZERO; 4],
        "all-dummy batch should have zero block hash"
    );

    // All nullifiers should be replaced with hashes of the pre-images.
    let expected: Vec<[F; 4]> = dummy_nullifier_pre_images
        .iter()
        .map(|p| hash_dummy_nullifier_pre_image_native(*p))
        .collect();
    assert_eq!(
        nullifier_region(pis, pis_list.len()),
        expected,
        "all-dummy nullifier region must contain the replacement hashes"
    );

    println!("Successfully aggregated all-dummy batch of 8 proofs!");
}

#[test]
fn recursive_aggregation_tree_mismatched_volume_fee_bps_fails() {
    let volume_fee_a = F::from_canonical_u64(10); // 0.1%
    let volume_fee_b = F::from_canonical_u64(50); // 0.5%

    let output_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);
    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
    for i in 0..8 {
        // Proof 3 has a different volume_fee_bps
        let volume_fee_bps = if i == 3 { volume_fee_b } else { volume_fee_a };
        pis_list.push(make_pi_from_felts(
            asset_id,
            output_felts[i],
            F::ZERO,
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            [F::ZERO; 8],
            common_block_hash,
            common_block_number,
        ));
    }

    let leaves = pis_list
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();
    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let res = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
    );

    assert!(
        res.is_err(),
        "expected failure due to mismatched volume_fee_bps"
    );
}

#[test]
fn recursive_aggregation_tree_exit_sum_overflow_fails() {
    // Test that exit amounts near u32::MAX that would overflow when summed are rejected
    // Use exit accounts that will collide (same account for multiple proofs)
    // so their amounts get summed
    let common_exit: [F; 8] = limbs8_u64_to_felts(EXIT_ACCOUNTS[0]);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);

    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);
    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    // Each proof has output near u32::MAX / 2, so 3+ proofs to same exit will overflow
    let large_amount = F::from_canonical_u64((u32::MAX / 2) as u64);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
    for nullifier in &nullifiers_felts {
        pis_list.push(make_pi_from_felts(
            asset_id,
            large_amount, // All proofs send to same exit, will overflow u32
            F::ZERO,
            volume_fee_bps,
            *nullifier,
            common_exit, // Same exit account for all
            [F::ZERO; 8],
            common_block_hash,
            common_block_number,
        ));
    }

    let leaves = pis_list
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();
    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let res = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images,
    );

    assert!(
        res.is_err(),
        "expected failure due to exit sum overflow (exceeds 32-bit range)"
    );
}

#[test]
fn recursive_aggregation_dummy_nullifiers_are_replaced() {
    // Verify that dummy proof nullifiers are actually replaced with hashes of pre-images
    // (more thorough check than the existing mixed-dummy test)
    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);
    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);

    // 1 real proof
    pis_list.push(make_pi_from_felts(
        asset_id,
        F::from_canonical_u64(100),
        F::ZERO,
        volume_fee_bps,
        nullifiers_felts[0],
        exits_felts[0],
        [F::ZERO; 8],
        common_block_hash,
        common_block_number,
    ));

    // 7 dummy proofs with distinct nullifiers that should be replaced
    let dummy_exit = [F::ZERO; 8];
    let dummy_block_hash = [F::ZERO; 4];
    for nullifier in nullifiers_felts.iter().skip(1) {
        pis_list.push(make_pi_from_felts(
            asset_id,
            F::ZERO,
            F::ZERO,
            volume_fee_bps,
            *nullifier, // Original nullifier (should be replaced)
            dummy_exit,
            dummy_exit,
            dummy_block_hash,
            F::ZERO,
        ));
    }

    let leaves = pis_list
        .clone()
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();

    let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

    let (root_proof, root_verifier) = aggregate_proofs_private_batch(
        proofs,
        leaf_common,
        leaf_verifier_only,
        dummy_nullifier_pre_images.clone(),
    )
    .unwrap();

    root_verifier.verify(root_proof.clone()).unwrap();

    let pis = &root_proof.public_inputs;
    let region = nullifier_region(pis, pis_list.len());

    // Region = the preserved real nullifier plus the dummy replacement hashes.
    let mut expected: Vec<[F; 4]> = vec![nullifiers_felts[0]];
    expected.extend(
        dummy_nullifier_pre_images
            .iter()
            .skip(1)
            .map(|p| hash_dummy_nullifier_pre_image_native(*p)),
    );
    assert_eq!(
        region, expected,
        "region must contain the real nullifier and every dummy replacement hash"
    );

    // No dummy slot's ORIGINAL nullifier may leak into the output.
    for original in nullifiers_felts.iter().skip(1) {
        assert!(
            !region.contains(original),
            "original dummy nullifier must be replaced, not forwarded"
        );
    }

    println!(
        "Verified dummy nullifier replacement for {} dummy proofs",
        7
    );
}

/// The private switch witness may route the verified nullifier multiset into
/// any requested order without changing any digest contents.
#[test]
fn nullifier_region_follows_private_permutation() {
    const N_LEAF: usize = 4;

    let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
    let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
    let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);

    let common_block_hash = block_hashes_felts[0];
    let common_block_number = F::from_canonical_u64(42);
    let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
    let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

    let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(N_LEAF);
    for i in 0..N_LEAF {
        pis_list.push(make_pi_from_felts(
            asset_id,
            F::from_canonical_u64(100 + i as u64),
            F::ZERO,
            volume_fee_bps,
            nullifiers_felts[i],
            exits_felts[i],
            [F::ZERO; 8],
            common_block_hash,
            common_block_number,
        ));
    }

    let leaves = pis_list
        .clone()
        .into_iter()
        .map(prove_fake_leaf_standalone)
        .collect::<Vec<_>>();
    let leaf_common = leaves[0].1.common.clone();
    let leaf_verifier_only = leaves[0].1.verifier_only.clone();
    let proofs = leaves
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();

    let permutation = vec![2, 0, 3, 1];
    let (root_proof, root_verifier) = aggregate_proofs_private_batch_with_permutation(
        proofs,
        leaf_common,
        leaf_verifier_only,
        deterministic_dummy_nullifier_pre_images(N_LEAF),
        permutation.clone(),
    )
    .unwrap();
    root_verifier.verify(root_proof.clone()).unwrap();

    let got = nullifier_region(&root_proof.public_inputs, N_LEAF);
    let expected: Vec<[F; 4]> = permutation.iter().map(|&i| nullifiers_felts[i]).collect();
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

/// Test that private-batch rejects proofs from a malicious circuit when built with
/// the legitimate verifier key baked in as constants.
#[test]
fn private_batch_rejects_malicious_circuit_proofs() {
    // Build the "legitimate" leaf circuit (with real constraints)
    let (legit_circuit, _legit_targets) = build_fake_leaf_circuit();

    // Build a MALICIOUS circuit (no constraints)
    let (malicious_circuit, malicious_targets) = build_malicious_leaf_circuit();

    // Build private-batch with LEGITIMATE verifier key baked in
    let private_batch_config = CircuitConfig::standard_recursion_config();
    let private_batch_circuit = PrivateBatchCircuit::new(
        private_batch_config,
        &legit_circuit.common,
        &legit_circuit.verifier_only, // SECURITY: Baked as constants
        1,
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    // Generate a malicious proof with FAKE values
    let fake_public_inputs: [u64; LEAF_PI_LEN] = [
        999,        // asset_id
        0xFFFFFFFF, // output_amount_1 - would fail range_check in legit circuit
        0xFFFFFFFF, // output_amount_2 - would fail range_check in legit circuit
        9999,       // volume_fee_bps - way over 100%
        0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321, // fake nullifier
        0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, // fake exit_1
        0xEEEEEEEE, 0xFFFFFFFF, 0x11111111, 0x22222222, // fake exit_2
        0x33333333, 0x44444444, 0x55555555, 0x66666666, // fake block_hash
        9999999,    // fake block_number
        0xFFFFFFFF, // fake input_amount
    ];

    let mut pw = PartialWitness::new();
    for (i, &val) in fake_public_inputs.iter().enumerate() {
        pw.set_target(malicious_targets[i], F::from_canonical_u64(val))
            .unwrap();
    }

    let malicious_proof = malicious_circuit.prove(pw).expect("prove malicious");

    // Try to use malicious proof in private-batch - this should FAIL
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&private_batch_targets.leaf_proofs[0], &malicious_proof)
        .unwrap();

    for pre_image in &private_batch_targets.dummy_nullifier_pre_images {
        for (i, &t) in pre_image.iter().enumerate() {
            pw.set_target(t, F::from_canonical_u64(i as u64)).unwrap();
        }
    }

    // private-batch proof generation should FAIL because the proof doesn't match the baked verifier key
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        private_batch_data.prove(pw)
    }));
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "private-batch should reject proofs from malicious circuit"
    );
}

/// Test that private-batch correctly accepts legitimate proofs after the security fix.
#[test]
fn private_batch_accepts_legitimate_proofs_after_fix() {
    // Build legitimate circuit
    let (legit_circuit, legit_targets) = build_fake_leaf_circuit();

    // Build private-batch with legitimate verifier key baked in
    let private_batch_config = CircuitConfig::standard_recursion_config();
    let private_batch_circuit = PrivateBatchCircuit::new(
        private_batch_config,
        &legit_circuit.common,
        &legit_circuit.verifier_only,
        1,
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    // Generate a LEGITIMATE proof with valid values
    let valid_public_inputs: [u64; LEAF_PI_LEN] = [
        0,    // asset_id
        1000, // output_amount_1 - valid u32
        2000, // output_amount_2 - valid u32
        100,  // volume_fee_bps - valid (1%)
        0x11111111, 0x22222222, 0x33333333, 0x44444444, // nullifier
        0x11111111, 0x22222222, 0x33333333, 0x44444444, // exit_1
        0x55555555, 0x66666666, 0x77777777, 0x88888888, // exit_2
        0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, // block_hash
        12345,      // block_number
        3031,       // input_amount: ceil(3000 * 10000 / 9900)
    ];

    let mut pw = PartialWitness::new();
    for (i, &val) in valid_public_inputs.iter().enumerate() {
        pw.set_target(legit_targets[i], F::from_canonical_u64(val))
            .unwrap();
    }

    let legit_proof = legit_circuit.prove(pw).expect("prove legit");

    // Use legitimate proof in private-batch - this should succeed
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&private_batch_targets.leaf_proofs[0], &legit_proof)
        .unwrap();

    for pre_image in &private_batch_targets.dummy_nullifier_pre_images {
        for (i, &t) in pre_image.iter().enumerate() {
            pw.set_target(t, F::from_canonical_u64(i as u64)).unwrap();
        }
    }

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

    // Structurally impossible: below the Poseidon gate wire floor.
    let mut narrow = wormhole_private_batch_circuit_config();
    narrow.num_wires = 134;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PrivateBatchCircuit::new(narrow, &leaf.common, &leaf.verifier_only, 1)
    }));
    let err = result
        .expect("pathological num_wires must yield a controlled error, not a panic")
        .err()
        .expect("num_wires below the Poseidon gate floor must be rejected");
    assert!(err.to_string().contains("num_wires"), "got: {err}");

    // Resource-pathological: oversized FRI rate (exponential LDE size).
    let mut huge_rate = wormhole_private_batch_circuit_config();
    huge_rate.fri_config.rate_bits = 63;
    let err = PrivateBatchCircuit::new(huge_rate, &leaf.common, &leaf.verifier_only, 1)
        .err()
        .expect("oversized rate_bits must be rejected before construction");
    assert!(err.to_string().contains("rate_bits"), "got: {err}");
}

/// The constructor must reject inner circuits whose public-input length
/// doesn't match the fixed leaf layout with a normal error, not a
/// panic mid-construction (the wrapper indexes fixed PI offsets).
#[test]
fn new_rejects_non_leaf_shaped_inner_circuit() {
    // A valid circuit with the wrong number of public inputs (5, not 22).
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let ts = builder.add_virtual_targets(5);
    builder.register_public_inputs(&ts);
    let wrong_shape = builder.build::<C>();

    let err = PrivateBatchCircuit::new(config, &wrong_shape.common, &wrong_shape.verifier_only, 1)
        .err()
        .expect("non-leaf-shaped inner circuit must be rejected");
    assert!(err.to_string().contains("num_public_inputs"), "got: {err}");
}

/// The witness filler must reject proofs whose public-input length doesn't
/// match the proof targets at its Result boundary: plonky2's internal zip
/// would otherwise silently leave trailing PI targets unset.
#[test]
fn witness_fill_rejects_wrong_pi_length_proof() {
    let (leaf, leaf_targets) = build_fake_leaf_circuit();
    let mut pw = PartialWitness::new();
    for t in leaf_targets.iter() {
        pw.set_target(*t, F::ZERO).unwrap();
    }
    let mut proof = leaf.prove(pw).unwrap();
    proof.public_inputs.pop();

    let targets = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        1,
    )
    .unwrap()
    .targets();

    let mut pw = PartialWitness::new();
    let err = fill_private_batch_witness(
        &mut pw,
        &targets,
        &[proof],
        &deterministic_dummy_nullifier_pre_images(1),
        &[0],
    )
    .expect_err("truncated proof public inputs must be rejected");
    assert!(err.to_string().contains("public inputs"), "got: {err}");
}

// -------------------------------------------------------------------------
// Witness-fill proof-shape preflight
//
// A proof with the expected 22 public inputs can still carry internally
// inconsistent proof vectors. The pinned qp-plonky2 witness writer assigns
// those through zip_eq / debug-only length checks, so without a full shape
// preflight a malformed proof panics inside fill_private_batch_witness
// (or silently leaves targets unset) instead of returning Err.
// -------------------------------------------------------------------------

/// Prove one valid fake leaf and build matching 1-slot private-batch targets.
fn valid_leaf_proof_and_targets() -> (
    ProofWithPublicInputs<F, C, D>,
    super::PrivateBatchCircuitTargets,
) {
    let (leaf, leaf_targets) = build_fake_leaf_circuit();
    let mut pw = PartialWitness::new();
    for t in leaf_targets.iter() {
        pw.set_target(*t, F::ZERO).unwrap();
    }
    let proof = leaf.prove(pw).unwrap();

    let targets = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        1,
    )
    .unwrap()
    .targets();

    (proof, targets)
}

fn fill_witness_with_proof(
    targets: &super::PrivateBatchCircuitTargets,
    proof: ProofWithPublicInputs<F, C, D>,
) -> Result<()> {
    let mut pw = PartialWitness::new();
    fill_private_batch_witness(
        &mut pw,
        targets,
        &[proof],
        &deterministic_dummy_nullifier_pre_images(1),
        &[0],
    )
}

/// Control: an untampered proof must still pass the shape preflight.
#[test]
fn witness_fill_accepts_well_shaped_proof() {
    let (proof, targets) = valid_leaf_proof_and_targets();
    fill_witness_with_proof(&targets, proof)
        .expect("a valid, well-shaped proof must fill the witness");
}

#[test]
fn witness_fill_rejects_invalid_nullifier_permutation() {
    let (proof, targets) = valid_leaf_proof_and_targets();
    let pre_images = deterministic_dummy_nullifier_pre_images(1);

    let mut pw = PartialWitness::new();
    let err = fill_private_batch_witness(
        &mut pw,
        &targets,
        std::slice::from_ref(&proof),
        &pre_images,
        &[],
    )
    .expect_err("short nullifier permutation must be rejected");
    assert!(err.to_string().contains("length mismatch"), "got: {err}");

    let mut pw = PartialWitness::new();
    let err = fill_private_batch_witness(&mut pw, &targets, &[proof], &pre_images, &[1])
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
