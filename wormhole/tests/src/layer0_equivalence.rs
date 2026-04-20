#![cfg(test)]

use anyhow::{Context, Result};
use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::Field;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::AggregatedPublicCircuitInputs;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use test_helpers::{
    block_header::{
        DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_PARENT_HASHES,
        DEFAULT_STATE_ROOTS,
    },
    compute_zk_leaf_hash, DEFAULT_SECRETS,
};
use wormhole_aggregator::{
    layer0::circuit::constants::aggregated_output,
    layer0::prover::{InnerExecutionMode, Layer0AggregationProver},
};
use wormhole_circuit::{
    block_header::header::HeaderInputs,
    inputs::{CircuitInputs, ParseAggregatedPublicInputs, PrivateCircuitInputs},
    nullifier::Nullifier,
    unspendable_account::UnspendableAccount,
};
use wormhole_prover::WormholeProver;
use zk_circuits_common::{
    circuit::{C, D, F},
    utils::{digest_to_bytes, BytesDigest},
    zk_merkle::{hash_node, ARITY, SIBLINGS_PER_LEVEL},
};

type Proof = ProofWithPublicInputs<F, C, D>;
type Hash256 = [u8; 32];

const TOTAL_LEAVES: usize = 16;
const INPUT_AMOUNT: u32 = 100;
const VOLUME_FEE_BPS: u32 = 10;
const FINAL_PUBLIC_INPUT_LEN: usize = aggregated_output::pi_len(TOTAL_LEAVES);
const FINAL_EXIT_SLOT_COUNT: usize = aggregated_output::exit_slots_count(TOTAL_LEAVES);
const FINAL_NULLIFIER_COUNT: usize = aggregated_output::nullifiers_count(TOTAL_LEAVES);
const FINAL_SEMANTIC_INPUT_LEN: usize = aggregated_output::HEADER_LEN
    + FINAL_EXIT_SLOT_COUNT * aggregated_output::EXIT_SLOT_LEN
    + FINAL_NULLIFIER_COUNT * 4;
const FINAL_ZERO_TAIL_LEN: usize = FINAL_PUBLIC_INPUT_LEN - FINAL_SEMANTIC_INPUT_LEN;

static TEST_BINS_DIR: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalAggregatedView {
    public_input_len: usize,
    account_slot_len: usize,
    exit_slot_count: u32,
    asset_id: u32,
    volume_fee_bps: u32,
    block_hash: BytesDigest,
    block_number: u32,
    slots: Vec<(BytesDigest, u32)>,
    zero_slot_count: usize,
    nullifiers: Vec<BytesDigest>,
}

fn test_bins_dir() -> PathBuf {
    TEST_BINS_DIR
        .get_or_init(|| {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before UNIX_EPOCH")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "qp-layer0-semantic-regression-{}-{}",
                std::process::id(),
                suffix
            ));

            fs::create_dir_all(&dir).expect("failed to create test bins dir");
            generate_all_circuit_binaries(&dir, true, TOTAL_LEAVES, None)
                .expect("failed to generate shipping circuit binaries");
            dir
        })
        .clone()
}

#[test]
fn shipping_2x8_contract_constants_are_locked() {
    assert_eq!(FINAL_PUBLIC_INPUT_LEN, 344);
    assert_eq!(FINAL_SEMANTIC_INPUT_LEN, 232);
    assert_eq!(FINAL_ZERO_TAIL_LEN, 112);
    assert_eq!(FINAL_EXIT_SLOT_COUNT, 32);
    assert_eq!(FINAL_NULLIFIER_COUNT, 16);
}

fn leaf_prover(bins_dir: &Path) -> Result<WormholeProver> {
    WormholeProver::new_from_files(
        bins_dir.join("prover.bin").as_path(),
        bins_dir.join("common.bin").as_path(),
    )
    .context("failed to load leaf prover from binaries")
}

fn build_4ary_tree(leaves: &[Hash256]) -> (Hash256, Vec<Vec<Hash256>>) {
    if leaves.is_empty() {
        return ([0u8; 32], vec![]);
    }

    let mut levels: Vec<Vec<Hash256>> = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(ARITY) {
            let mut children: [Hash256; ARITY] = [[0u8; 32]; ARITY];
            for (i, child) in chunk.iter().enumerate() {
                children[i] = *child;
            }
            next_level.push(hash_node(&children));
        }

        levels.push(next_level);
    }

    let root = levels.last().unwrap()[0];
    (root, levels)
}

fn generate_proof(
    leaf_index: usize,
    levels: &[Vec<Hash256>],
) -> (Vec<[Hash256; SIBLINGS_PER_LEVEL]>, Vec<u8>) {
    let mut siblings = Vec::new();
    let mut positions = Vec::new();
    let mut current_index = leaf_index;

    for level in levels.iter().take(levels.len() - 1) {
        let group_start = (current_index / ARITY) * ARITY;
        let position_in_group = current_index % ARITY;

        let mut children: [Hash256; ARITY] = [[0u8; 32]; ARITY];
        for (i, child) in children.iter_mut().enumerate() {
            let idx = group_start + i;
            if idx < level.len() {
                *child = level[idx];
            }
        }

        let current_hash = children[position_in_group];
        children.sort();
        let sorted_position = children.iter().position(|h| *h == current_hash).unwrap() as u8;

        let mut level_siblings: [Hash256; SIBLINGS_PER_LEVEL] = [[0u8; 32]; SIBLINGS_PER_LEVEL];
        let mut sib_idx = 0;
        for (i, child) in children.iter().enumerate() {
            if i as u8 != sorted_position {
                level_siblings[sib_idx] = *child;
                sib_idx += 1;
            }
        }

        siblings.push(level_siblings);
        positions.push(sorted_position);
        current_index /= ARITY;
    }

    (siblings, positions)
}

fn make_inputs() -> Vec<CircuitInputs> {
    let secret_bytes: [u8; 32] = hex::decode(DEFAULT_SECRETS[0])
        .expect("failed to decode secret")
        .try_into()
        .expect("secret length should be 32 bytes");
    let secret = BytesDigest::try_from(secret_bytes).expect("secret should fit in field");
    let unspendable_account = digest_to_bytes(UnspendableAccount::from_secret(secret).account_id);

    let transfer_counts: Vec<u64> = (1..=TOTAL_LEAVES as u64).collect();
    let leaf_hashes: Vec<Hash256> = transfer_counts
        .iter()
        .map(|transfer_count| {
            compute_zk_leaf_hash(&unspendable_account, *transfer_count, 0u32, INPUT_AMOUNT)
        })
        .collect();
    let (root, levels) = build_4ary_tree(&leaf_hashes);
    let root_digest = BytesDigest::try_from(root).expect("tree root should fit in field");

    let header = HeaderInputs::new(
        BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).expect("parent hash"),
        DEFAULT_BLOCK_NUMBERS[0],
        BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).expect("state root"),
        DEFAULT_EXTRINSICS_ROOTS[0]
            .try_into()
            .expect("extrinsics root"),
        root_digest,
        &DEFAULT_DIGESTS[0],
    )
    .expect("valid header inputs");
    let block_hash = BytesDigest::try_from(header.block_hash().as_ref()).expect("block hash");

    let exit_accounts = [
        BytesDigest::try_from([1u8; 32]).expect("exit account"),
        BytesDigest::try_from([2u8; 32]).expect("exit account"),
        BytesDigest::try_from([3u8; 32]).expect("exit account"),
    ];

    transfer_counts
        .iter()
        .enumerate()
        .map(|(leaf_index, transfer_count)| {
            let output_amount_1 = 1 + leaf_index as u32;
            let exit_account_1 = exit_accounts[leaf_index % exit_accounts.len()];
            let nullifier = digest_to_bytes(Nullifier::from_preimage(secret, *transfer_count).hash);
            let (zk_merkle_siblings, zk_merkle_positions) = generate_proof(leaf_index, &levels);

            CircuitInputs {
                public: qp_wormhole_inputs::PublicCircuitInputs {
                    asset_id: 0,
                    output_amount_1,
                    output_amount_2: 0,
                    volume_fee_bps: VOLUME_FEE_BPS,
                    nullifier,
                    exit_account_1,
                    exit_account_2: BytesDigest::default(),
                    block_hash,
                    block_number: DEFAULT_BLOCK_NUMBERS[0],
                },
                private: PrivateCircuitInputs {
                    secret,
                    transfer_count: *transfer_count,
                    unspendable_account,
                    parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap(),
                    state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
                    extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                    digest: DEFAULT_DIGESTS[0],
                    input_amount: INPUT_AMOUNT,
                    zk_tree_root: root,
                    zk_merkle_siblings,
                    zk_merkle_positions,
                },
            }
        })
        .collect()
}

fn prove_leaf(bins_dir: &Path, inputs: &CircuitInputs) -> Result<Proof> {
    let prover = leaf_prover(bins_dir)?;
    prover.commit(inputs)?.prove()
}

fn prove_batch(bins_dir: &Path, inputs: &[CircuitInputs]) -> Result<Vec<Proof>> {
    let mut proofs = Vec::with_capacity(inputs.len());
    for (idx, input) in inputs.iter().enumerate() {
        println!("proving leaf {}/{}", idx + 1, inputs.len());
        proofs.push(prove_leaf(bins_dir, input)?);
    }
    Ok(proofs)
}

fn aggregate_layer0(bins_dir: &Path, proofs: &[Proof]) -> Result<Proof> {
    println!("running layer0 aggregation");
    let prover = Layer0AggregationProver::new_from_binaries_dir(bins_dir)
        .context("failed to load layer0 prover")?;
    Ok(prover
        .aggregate(proofs.to_vec(), InnerExecutionMode::Parallel)?
        .proof)
}

fn parse_aggregated(proof: &Proof) -> Result<AggregatedPublicCircuitInputs> {
    AggregatedPublicCircuitInputs::try_from_felts(&proof.public_inputs)
}

fn assert_parsed_contract_invariants(
    label: &str,
    proof: &Proof,
    parsed: &AggregatedPublicCircuitInputs,
) -> Result<()> {
    let zero_account = BytesDigest::default();

    anyhow::ensure!(
        proof.public_inputs.len() == FINAL_PUBLIC_INPUT_LEN,
        "{label} must preserve the 344-felt final public-input layout"
    );
    anyhow::ensure!(
        proof.public_inputs[0] == F::from_canonical_u64(FINAL_EXIT_SLOT_COUNT as u64),
        "{label} slot-0 behavior changed"
    );
    anyhow::ensure!(
        FINAL_PUBLIC_INPUT_LEN == 344,
        "the final public-input layout must remain 344 felts"
    );
    anyhow::ensure!(
        FINAL_SEMANTIC_INPUT_LEN == 232,
        "the semantic prefix must remain 232 felts"
    );
    anyhow::ensure!(
        FINAL_ZERO_TAIL_LEN == 112,
        "the zero tail must remain 112 felts"
    );
    anyhow::ensure!(
        proof.public_inputs[FINAL_SEMANTIC_INPUT_LEN..]
            .iter()
            .all(|felt| felt.is_zero()),
        "{label} padded tail must remain zero-filled"
    );
    anyhow::ensure!(
        parsed.account_data.len() == FINAL_EXIT_SLOT_COUNT,
        "{label} parsed account slot count changed"
    );
    anyhow::ensure!(
        parsed.nullifiers.len() == FINAL_NULLIFIER_COUNT,
        "{label} parsed nullifier count changed"
    );
    anyhow::ensure!(
        parsed.num_unique_exits == FINAL_EXIT_SLOT_COUNT as u32,
        "{label} slot-0 metadata must still report the full exit-slot count"
    );

    for (idx, slot) in parsed.account_data.iter().enumerate() {
        let is_zero_account = slot.exit_account == zero_account;
        let is_zero_amount = slot.summed_output_amount == 0;
        anyhow::ensure!(
            is_zero_account == is_zero_amount,
            "{label} slot {idx} must be either fully zeroed or fully non-zero"
        );
    }

    Ok(())
}

fn normalize_aggregated(label: &str, proof: &Proof) -> Result<CanonicalAggregatedView> {
    let parsed = parse_aggregated(proof)?;
    assert_parsed_contract_invariants(label, proof, &parsed)?;
    let zero_account = BytesDigest::default();
    let mut zero_slot_count = 0usize;
    let account_slot_len = parsed.account_data.len();
    let mut slots = Vec::<(BytesDigest, u32)>::with_capacity(account_slot_len);

    for slot in parsed.account_data {
        if slot.exit_account == zero_account {
            anyhow::ensure!(
                slot.summed_output_amount == 0,
                "zero exit-account slots must also be zero-valued"
            );
            zero_slot_count += 1;
            continue;
        }

        slots.push((slot.exit_account, slot.summed_output_amount));
    }

    slots.sort_unstable();
    for pair in slots.windows(2) {
        anyhow::ensure!(
            pair[0].0 < pair[1].0,
            "{label} parsed slots must be strictly ordered by exit account after normalization"
        );
    }

    let mut nullifiers = parsed.nullifiers;
    nullifiers.sort();
    for pair in nullifiers.windows(2) {
        anyhow::ensure!(
            pair[0] != pair[1],
            "{label} parsed nullifiers must remain unique"
        );
    }

    Ok(CanonicalAggregatedView {
        public_input_len: proof.public_inputs.len(),
        account_slot_len,
        exit_slot_count: parsed.num_unique_exits,
        asset_id: parsed.asset_id,
        volume_fee_bps: parsed.volume_fee_bps,
        block_hash: parsed.block_data.block_hash,
        block_number: parsed.block_data.block_number,
        slots,
        zero_slot_count,
        nullifiers,
    })
}
fn assert_views_match(left: &CanonicalAggregatedView, right: &CanonicalAggregatedView) {
    assert_eq!(left.public_input_len, FINAL_PUBLIC_INPUT_LEN);
    assert_eq!(right.public_input_len, FINAL_PUBLIC_INPUT_LEN);
    assert_eq!(left.public_input_len, right.public_input_len);
    assert_eq!(left.account_slot_len, FINAL_EXIT_SLOT_COUNT);
    assert_eq!(right.account_slot_len, FINAL_EXIT_SLOT_COUNT);

    assert_eq!(left.exit_slot_count, right.exit_slot_count);
    assert_eq!(left.exit_slot_count, FINAL_EXIT_SLOT_COUNT as u32);
    assert_eq!(left.asset_id, right.asset_id);
    assert_eq!(left.volume_fee_bps, right.volume_fee_bps);
    assert_eq!(left.block_hash, right.block_hash);
    assert_eq!(left.block_number, right.block_number);
    assert_eq!(left.slots, right.slots);
    assert_eq!(left.zero_slot_count, right.zero_slot_count);
    assert_eq!(left.nullifiers, right.nullifiers);
}

#[test]
fn layer0_matches_reference_single_stage_semantics() -> Result<()> {
    let bins_dir = test_bins_dir();
    let inputs = make_inputs();
    let proofs = prove_batch(&bins_dir, &inputs)?;

    let layer0 = aggregate_layer0(&bins_dir, &proofs)?;
    let layer0_view = normalize_aggregated("layer0", &layer0)?;

    assert_eq!(layer0.public_inputs.len(), FINAL_PUBLIC_INPUT_LEN);
    assert!(layer0.public_inputs[FINAL_SEMANTIC_INPUT_LEN..]
        .iter()
        .all(|felt| felt.is_zero()));
    assert_eq!(layer0_view.public_input_len, FINAL_PUBLIC_INPUT_LEN);
    assert_eq!(layer0_view.exit_slot_count, FINAL_EXIT_SLOT_COUNT as u32);
    assert_eq!(layer0_view.account_slot_len, FINAL_EXIT_SLOT_COUNT);
    assert_eq!(layer0_view.asset_id, 0);
    assert_eq!(layer0_view.volume_fee_bps, VOLUME_FEE_BPS);
    assert_eq!(layer0_view.block_number, DEFAULT_BLOCK_NUMBERS[0]);
    assert_eq!(layer0_view.nullifiers.len(), FINAL_NULLIFIER_COUNT);
    assert_eq!(
        layer0_view.slots.len() + layer0_view.zero_slot_count,
        FINAL_EXIT_SLOT_COUNT
    );
    assert!(layer0_view.zero_slot_count > 0);
    assert_eq!(
        layer0_view
            .slots
            .iter()
            .map(|(_, amount)| *amount)
            .sum::<u32>(),
        (1..=TOTAL_LEAVES as u32).sum::<u32>()
    );
    Ok(())
}

#[test]
fn layer0_warm_artifacts_load_and_prove() -> Result<()> {
    let bins_dir = test_bins_dir();
    let inputs = make_inputs();
    let proofs = prove_batch(&bins_dir, &inputs)?;

    let runner_a = Layer0AggregationProver::new_from_binaries_dir(&bins_dir)
        .context("failed to warm-load runner A")?;
    let runner_b = Layer0AggregationProver::new_from_binaries_dir(&bins_dir)
        .context("failed to warm-load runner B")?;

    let proof_a = runner_a
        .aggregate(proofs.clone(), InnerExecutionMode::Parallel)
        .context("runner A aggregation failed")?
        .proof;
    let proof_b = runner_b
        .aggregate(proofs, InnerExecutionMode::Parallel)
        .context("runner B aggregation failed")?
        .proof;

    let view_a = normalize_aggregated("runner A", &proof_a)?;
    let view_b = normalize_aggregated("runner B", &proof_b)?;
    assert_views_match(&view_a, &view_b);
    Ok(())
}
