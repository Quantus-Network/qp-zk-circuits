#![cfg(test)]

use anyhow::{Context, Result};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::target::Target,
    plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs},
};
use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};
use wormhole_aggregator::layer0::{
    circuit::constants::{
        aggregated_output, inner_circuit_config, outer_circuit_config, ASSET_ID_START,
        BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START, EXIT_2_START, INNER_NUM_LEAVES,
        LEAF_PI_LEN, NULLIFIER_START, OUTER_CHILD_EXIT_SLOTS_START, OUTER_CHILD_EXIT_SLOT_LEN,
        OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START, TOTAL_NUM_LEAVES, VOLUME_FEE_BPS_START,
    },
    prover::{
        inner::{InnerAggregationArtifacts, InnerAggregationInputs},
        outer::{OuterAggregationArtifacts, OuterAggregationInputs},
    },
};
use zk_circuits_common::circuit::{C, D, F};

type Proof = ProofWithPublicInputs<F, C, D>;

#[derive(Debug, PartialEq, Eq)]
struct NormalizedLayer0View {
    public_input_len: usize,
    exit_slot_count: u64,
    asset_id: u64,
    volume_fee_bps: u64,
    block_hash: [u64; 4],
    block_number: u64,
    slots: Vec<([u64; 4], u64)>,
    zero_slot_count: usize,
    nullifiers: Vec<[u64; 4]>,
}

const FINAL_PUBLIC_INPUT_LEN: usize = aggregated_output::pi_len(TOTAL_NUM_LEAVES);
const FINAL_EXIT_SLOT_COUNT: usize = aggregated_output::exit_slots_count(TOTAL_NUM_LEAVES);
const FINAL_NULLIFIER_COUNT: usize = aggregated_output::nullifiers_count(TOTAL_NUM_LEAVES);
const FINAL_SEMANTIC_INPUT_LEN: usize = aggregated_output::HEADER_LEN
    + FINAL_EXIT_SLOT_COUNT * aggregated_output::EXIT_SLOT_LEN
    + FINAL_NULLIFIER_COUNT * 4;
const FINAL_ZERO_TAIL_LEN: usize = FINAL_PUBLIC_INPUT_LEN - FINAL_SEMANTIC_INPUT_LEN;

struct LeafFixture {
    data: CircuitData<F, C, D>,
    targets: [Target; LEAF_PI_LEN],
    dummy_proof: Proof,
}

impl LeafFixture {
    fn new() -> Self {
        let (data, targets) = build_fake_leaf_circuit();
        let dummy_proof = prove_fake_leaf(&data, &targets, dummy_leaf_pi());
        Self {
            data,
            targets,
            dummy_proof,
        }
    }

    fn prove(&self, public_inputs: [F; LEAF_PI_LEN]) -> Proof {
        prove_fake_leaf(&self.data, &self.targets, public_inputs)
    }
}

#[test]
fn compact_child_contract_constants_are_locked() {
    assert_eq!(FINAL_PUBLIC_INPUT_LEN, 344);
    assert_eq!(FINAL_SEMANTIC_INPUT_LEN, 232);
    assert_eq!(FINAL_ZERO_TAIL_LEN, 112);
    assert_eq!(FINAL_EXIT_SLOT_COUNT, 32);
    assert_eq!(FINAL_NULLIFIER_COUNT, 16);
}

#[test]
fn compact_child_inner_config_is_non_zk_and_outer_config_is_zk() {
    assert_eq!(
        inner_circuit_config().zk_config,
        plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config().zk_config
    );
    assert_ne!(
        inner_circuit_config().zk_config,
        outer_circuit_config().zk_config
    );
}

#[test]
fn compact_child_padding_does_not_force_dummy_asset_or_fee_values() -> Result<()> {
    let fixture = LeafFixture::new();
    let proofs = make_leaf_proofs(&fixture, 3, 7, 42);

    let compact_child = aggregate_compact_child(&fixture, &proofs)?;

    assert_final_contract("padded compact child", &compact_child);
    assert_eq!(
        compact_child.public_inputs[aggregated_output::ASSET_ID_OFFSET],
        F::from_canonical_u64(7)
    );
    assert_eq!(
        compact_child.public_inputs[aggregated_output::VOLUME_FEE_BPS_OFFSET],
        F::from_canonical_u64(42)
    );
    Ok(())
}

#[test]
fn compact_child_inner_outputs_are_canonical_for_reordered_inputs() -> Result<()> {
    let fixture = LeafFixture::new();
    let proofs = make_leaf_proofs(&fixture, INNER_NUM_LEAVES, 0, 10);
    let mut reversed = proofs.clone();
    reversed.reverse();

    let original = prove_inner_batch(&fixture, proofs)?;
    let reordered = prove_inner_batch(&fixture, reversed)?;

    assert_eq!(original.public_inputs, reordered.public_inputs);
    Ok(())
}

#[test]
fn public_input_order_is_deterministic_for_shuffled_compact_child_inputs() -> Result<()> {
    let fixture = LeafFixture::new();
    let proofs = make_leaf_proofs(&fixture, TOTAL_NUM_LEAVES, 0, 10);
    let shuffled = (0..TOTAL_NUM_LEAVES)
        .map(|idx| proofs[(idx * 5 + 3) % TOTAL_NUM_LEAVES].clone())
        .collect::<Vec<_>>();

    let original = aggregate_compact_child(&fixture, &proofs)?;
    let shuffled = aggregate_compact_child(&fixture, &shuffled)?;

    assert_eq!(original.public_inputs, shuffled.public_inputs);
    Ok(())
}

#[test]
fn zero_exit_positive_amount_in_first_output_is_rejected_before_inner_aggregation() {
    let fixture = LeafFixture::new();
    let proof = fixture.prove(leaf_pi_with_zero_exit_positive_amount(0, 0));

    let err = inner_artifacts(&fixture)
        .new_session()
        .commit(InnerAggregationInputs {
            proofs: vec![proof],
        })
        .unwrap_err();

    assert!(
        err.to_string().contains("zero exit_account"),
        "unexpected error: {err}"
    );
}

#[test]
fn zero_exit_positive_amount_in_second_output_is_rejected_before_inner_aggregation() {
    let fixture = LeafFixture::new();
    let proof = fixture.prove(leaf_pi_with_zero_exit_positive_amount(1, 0));

    let err = inner_artifacts(&fixture)
        .new_session()
        .commit(InnerAggregationInputs {
            proofs: vec![proof],
        })
        .unwrap_err();

    assert!(
        err.to_string().contains("zero exit_account"),
        "unexpected error: {err}"
    );
}

#[test]
fn zero_exit_positive_amount_across_inner_groups_is_rejected() {
    let fixture = LeafFixture::new();
    let mut proofs = make_leaf_proofs(&fixture, INNER_NUM_LEAVES, 0, 10);
    proofs.push(fixture.prove(leaf_pi_with_zero_exit_positive_amount(
        0,
        INNER_NUM_LEAVES as u64,
    )));

    let err = aggregate_compact_child(&fixture, &proofs).unwrap_err();

    let err = format!("{err:?}");
    assert!(err.contains("zero exit_account"), "unexpected error: {err}");
}

#[test]
fn zero_exit_zero_amount_empty_slot_is_accepted_with_dummy_padding() -> Result<()> {
    let fixture = LeafFixture::new();
    let proof = fixture.prove(real_leaf_pi(0, 0, 10, 25));

    let aggregated = aggregate_compact_child(&fixture, &[proof])?;

    assert_final_contract("zero exit empty slot", &aggregated);
    Ok(())
}

#[test]
fn nonzero_exit_positive_amount_is_accepted() -> Result<()> {
    let fixture = LeafFixture::new();
    let proof = fixture.prove(real_leaf_pi(0, 0, 10, 25));

    let inner = prove_inner_batch(&fixture, vec![proof.clone()])?;
    let aggregated = aggregate_compact_child(&fixture, &[proof])?;

    let parsed = normalize_layer0_view("nonzero exit positive amount", &aggregated);
    assert!(parsed.slots.iter().any(|(_, amount)| *amount == 25));
    assert_eq!(
        inner.public_inputs[aggregated_output::ASSET_ID_OFFSET],
        F::ZERO
    );
    Ok(())
}

#[test]
fn outer_rejects_zero_exit_positive_amount_in_inner_output() -> Result<()> {
    let fixture = LeafFixture::new();
    let inner_artifacts = inner_artifacts(&fixture);
    let outer_artifacts = outer_artifacts(&inner_artifacts);
    let inner_a = inner_artifacts
        .new_session()
        .commit(InnerAggregationInputs {
            proofs: vec![fixture.prove(real_leaf_pi(0, 0, 10, 11))],
        })?
        .prove()?;
    let mut bad_inner_b = inner_artifacts
        .new_session()
        .commit(InnerAggregationInputs {
            proofs: vec![fixture.prove(real_leaf_pi(1, 0, 10, 12))],
        })?
        .prove()?;

    let empty_slot_base = OUTER_CHILD_EXIT_SLOTS_START + OUTER_CHILD_EXIT_SLOT_LEN;
    bad_inner_b.public_inputs[empty_slot_base] = F::from_canonical_u64(99);

    let err = outer_artifacts
        .new_session()
        .commit(OuterAggregationInputs {
            proofs: vec![inner_a, bad_inner_b],
        })
        .unwrap_err();

    assert!(
        err.to_string().contains("zero exit_account"),
        "unexpected error: {err}"
    );
    Ok(())
}

fn aggregate_compact_child(fixture: &LeafFixture, proofs: &[Proof]) -> Result<Proof> {
    let inner_artifacts = inner_artifacts(fixture);
    let outer_artifacts = outer_artifacts(&inner_artifacts);
    let mut proofs = proofs.to_vec();
    sort_proofs_canonically_for_test(&mut proofs);
    let (group_a, group_b) = split_for_inner_batches(&proofs);

    let inner_a = inner_artifacts
        .new_session()
        .commit(InnerAggregationInputs { proofs: group_a })
        .context("inner A commit failed")?
        .prove()
        .context("inner A proof failed")?;
    let inner_b = inner_artifacts
        .new_session()
        .commit(InnerAggregationInputs { proofs: group_b })
        .context("inner B commit failed")?
        .prove()
        .context("inner B proof failed")?;

    let proof = outer_artifacts
        .new_session()
        .commit(OuterAggregationInputs {
            proofs: vec![inner_a, inner_b],
        })
        .context("outer commit failed")?
        .prove()
        .context("outer proof failed")?;
    outer_artifacts
        .verifier_data
        .verify(proof.clone())
        .context("compact-child layer-0 verification failed")?;
    Ok(proof)
}

fn prove_inner_batch(fixture: &LeafFixture, proofs: Vec<Proof>) -> Result<Proof> {
    inner_artifacts(fixture)
        .new_session()
        .commit(InnerAggregationInputs { proofs })
        .context("inner commit failed")?
        .prove()
        .context("inner proof failed")
}

fn inner_artifacts(fixture: &LeafFixture) -> InnerAggregationArtifacts {
    InnerAggregationArtifacts::new(
        fixture.data.common.clone(),
        fixture.data.verifier_only.clone(),
        fixture.dummy_proof.clone(),
    )
}

fn outer_artifacts(inner: &InnerAggregationArtifacts) -> OuterAggregationArtifacts {
    OuterAggregationArtifacts::new(
        inner.verifier_data.common.clone(),
        inner.verifier_data.verifier_only.clone(),
    )
}

fn split_for_inner_batches(proofs: &[Proof]) -> (Vec<Proof>, Vec<Proof>) {
    let split_at = proofs.len().min(INNER_NUM_LEAVES);
    (proofs[..split_at].to_vec(), proofs[split_at..].to_vec())
}

fn sort_proofs_canonically_for_test(proofs: &mut [Proof]) {
    proofs.sort_by(|left, right| {
        left.public_inputs
            .iter()
            .map(PrimeField64::to_canonical_u64)
            .cmp(
                right
                    .public_inputs
                    .iter()
                    .map(PrimeField64::to_canonical_u64),
            )
    });
}

fn make_leaf_proofs(
    fixture: &LeafFixture,
    count: usize,
    asset_id: u64,
    volume_fee_bps: u64,
) -> Vec<Proof> {
    (0..count)
        .map(|idx| {
            fixture.prove(real_leaf_pi(
                idx as u64,
                asset_id,
                volume_fee_bps,
                1 + idx as u64,
            ))
        })
        .collect()
}

fn assert_final_contract(label: &str, proof: &Proof) {
    assert_eq!(
        proof.public_inputs.len(),
        FINAL_PUBLIC_INPUT_LEN,
        "{label} public input length changed"
    );
    assert_eq!(
        proof.public_inputs[aggregated_output::NUM_EXIT_SLOTS_OFFSET],
        F::from_canonical_u64(FINAL_EXIT_SLOT_COUNT as u64),
        "{label} exit slot metadata changed"
    );
    assert!(
        proof.public_inputs[FINAL_SEMANTIC_INPUT_LEN..]
            .iter()
            .all(|felt| felt.is_zero()),
        "{label} zero tail changed"
    );
}

fn normalize_layer0_view(label: &str, proof: &Proof) -> NormalizedLayer0View {
    assert_final_contract(label, proof);

    let mut slots = Vec::with_capacity(FINAL_EXIT_SLOT_COUNT);
    let mut zero_slot_count = 0;
    let slots_start = aggregated_output::exit_slots_start();
    for slot in 0..FINAL_EXIT_SLOT_COUNT {
        let base = slots_start + slot * aggregated_output::EXIT_SLOT_LEN;
        let amount = proof.public_inputs[base].to_canonical_u64();
        let exit = felt_digest(&proof.public_inputs[base + 1..base + 5]);
        if exit == [0; 4] {
            assert_eq!(amount, 0, "{label} zero exit slot has non-zero amount");
            zero_slot_count += 1;
        } else {
            slots.push((exit, amount));
        }
    }
    slots.sort_unstable();

    let nullifiers_start = aggregated_output::nullifiers_start(TOTAL_NUM_LEAVES);
    let mut nullifiers = (0..FINAL_NULLIFIER_COUNT)
        .map(|idx| {
            let base = nullifiers_start + idx * 4;
            felt_digest(&proof.public_inputs[base..base + 4])
        })
        .collect::<Vec<_>>();
    nullifiers.sort_unstable();

    NormalizedLayer0View {
        public_input_len: proof.public_inputs.len(),
        exit_slot_count: proof.public_inputs[aggregated_output::NUM_EXIT_SLOTS_OFFSET]
            .to_canonical_u64(),
        asset_id: proof.public_inputs[aggregated_output::ASSET_ID_OFFSET].to_canonical_u64(),
        volume_fee_bps: proof.public_inputs[aggregated_output::VOLUME_FEE_BPS_OFFSET]
            .to_canonical_u64(),
        block_hash: felt_digest(
            &proof.public_inputs
                [aggregated_output::BLOCK_HASH_OFFSET..aggregated_output::BLOCK_HASH_OFFSET + 4],
        ),
        block_number: proof.public_inputs[aggregated_output::BLOCK_NUMBER_OFFSET]
            .to_canonical_u64(),
        slots,
        zero_slot_count,
        nullifiers,
    }
}

fn felt_digest(felts: &[F]) -> [u64; 4] {
    core::array::from_fn(|idx| felts[idx].to_canonical_u64())
}

fn real_leaf_pi(
    idx: u64,
    asset_id: u64,
    volume_fee_bps: u64,
    output_amount: u64,
) -> [F; LEAF_PI_LEN] {
    let mut public_inputs = [F::ZERO; LEAF_PI_LEN];
    public_inputs[ASSET_ID_START] = F::from_canonical_u64(asset_id);
    public_inputs[OUTPUT_AMOUNT_1_START] = F::from_canonical_u64(output_amount);
    public_inputs[OUTPUT_AMOUNT_2_START] = F::ZERO;
    public_inputs[VOLUME_FEE_BPS_START] = F::from_canonical_u64(volume_fee_bps);
    public_inputs[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&digest(1_000 + idx * 10));
    public_inputs[EXIT_1_START..EXIT_1_START + 4].copy_from_slice(&digest(2_000 + idx * 10));
    public_inputs[EXIT_2_START..EXIT_2_START + 4].copy_from_slice(&[F::ZERO; 4]);
    public_inputs[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&digest(3_000));
    public_inputs[BLOCK_NUMBER_START] = F::from_canonical_u64(99);
    public_inputs
}

fn leaf_pi_with_zero_exit_positive_amount(output_idx: usize, idx: u64) -> [F; LEAF_PI_LEN] {
    let mut public_inputs = real_leaf_pi(idx, 0, 10, 7);
    match output_idx {
        0 => {
            public_inputs[OUTPUT_AMOUNT_1_START] = F::from_canonical_u64(7);
            public_inputs[EXIT_1_START..EXIT_1_START + 4].copy_from_slice(&[F::ZERO; 4]);
        }
        1 => {
            public_inputs[OUTPUT_AMOUNT_2_START] = F::from_canonical_u64(7);
            public_inputs[EXIT_2_START..EXIT_2_START + 4].copy_from_slice(&[F::ZERO; 4]);
        }
        _ => panic!("invalid output index"),
    }
    public_inputs
}

fn dummy_leaf_pi() -> [F; LEAF_PI_LEN] {
    let mut public_inputs = [F::ZERO; LEAF_PI_LEN];
    public_inputs[VOLUME_FEE_BPS_START] = F::from_canonical_u64(10);
    public_inputs
}

fn digest(seed: u64) -> [F; 4] {
    core::array::from_fn(|idx| F::from_canonical_u64(seed + idx as u64))
}
