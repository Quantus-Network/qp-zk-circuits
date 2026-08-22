use super::*;
use plonky2::field::types::PrimeField64;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{
    INPUT_AMOUNT_INDEX, PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN, VOLUME_FEE_BPS_INDEX,
};

use super::super::constants::AGGREGATOR_ADDRESS_LEN;
use crate::private_batch::circuit::circuit_logic::{
    PrivateBatchCircuit, PrivateBatchCircuitTargets,
};
use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

const NUM_LEAVES: usize = 2; // 2 leaf proofs per private-batch batch (fast)
const N_INNER: usize = 2; // 2 private-batch proofs aggregated into one public-batch proof
const TEST_VOLUME_FEE_BPS: u32 = 10;

/// Audit finding: the constructor forwarded the caller-supplied
/// `CircuitConfig` to `CircuitBuilder::new` unchecked. Structurally
/// impossible configs (e.g. `num_wires` below the Poseidon gate floor)
/// panicked deep inside plonky2 mid-construction, and resource-pathological
/// configs (e.g. an oversized FRI rate driving `2^(degree_bits+rate_bits)`
/// LDE allocations) sailed through construction and only exploded during
/// the expensive build/prove phase. Both classes must be rejected with a
/// controlled error before any builder work. Mirrors the private-batch
/// constructor test one layer down.
#[test]
fn new_rejects_pathological_circuit_configs() {
    use zk_circuits_common::circuit::wormhole_public_batch_circuit_config;

    let (leaf, _) = build_fake_leaf_circuit();
    let private_batch = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        1,
    )
    .unwrap()
    .build_verifier();

    // Structurally impossible: below the Poseidon gate wire floor.
    let mut narrow = wormhole_public_batch_circuit_config();
    narrow.num_wires = 134;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PublicBatchCircuit::new(
            narrow,
            private_batch.common.clone(),
            &private_batch.verifier_only,
            1,
            1,
        )
    }));
    let err = result
        .expect("pathological num_wires must yield a controlled error, not a panic")
        .err()
        .expect("num_wires below the Poseidon gate floor must be rejected");
    assert!(err.to_string().contains("num_wires"), "got: {err}");

    // Resource-pathological: oversized FRI rate (exponential LDE size).
    let mut huge_rate = wormhole_public_batch_circuit_config();
    huge_rate.fri_config.rate_bits = 63;
    let err = PublicBatchCircuit::new(
        huge_rate,
        private_batch.common.clone(),
        &private_batch.verifier_only,
        1,
        1,
    )
    .err()
    .expect("oversized rate_bits must be rejected before construction");
    assert!(err.to_string().contains("rate_bits"), "got: {err}");
}

/// Build one leaf PI array in the Bitcoin-style 2-output layout.
///
/// Layout (22 felts total):
/// - asset_id(1), output_amount_1(1), output_amount_2(1), volume_fee_bps(1)
/// - nullifier(4)
/// - exit_account_1(4) - 4 felts (8 bytes/felt)
/// - exit_account_2(4) - 4 felts (8 bytes/felt)
/// - block_hash(4), block_number(1), input_amount(1)
#[allow(clippy::too_many_arguments)]
fn make_leaf_pi(
    amount1: u32,
    amount2: u32,
    volume_fee_bps: u32,
    exit1: [u64; 4],
    exit2: [u64; 4],
    nullifier: [u64; 4],
    block_hash: [u64; 4],
    block_number: u32,
) -> [F; LEAF_PI_LEN] {
    make_leaf_pi_with_asset(
        0,
        amount1,
        amount2,
        volume_fee_bps,
        exit1,
        exit2,
        nullifier,
        block_hash,
        block_number,
    )
}

#[allow(clippy::too_many_arguments)]
fn make_leaf_pi_with_asset(
    asset_id: u32,
    amount1: u32,
    amount2: u32,
    volume_fee_bps: u32,
    exit1: [u64; 4],
    exit2: [u64; 4],
    nullifier: [u64; 4],
    block_hash: [u64; 4],
    block_number: u32,
) -> [F; LEAF_PI_LEN] {
    assert!(volume_fee_bps <= 10_000);
    let mut out = [F::ZERO; LEAF_PI_LEN];
    out[0] = F::from_canonical_u64(asset_id as u64);
    out[1] = F::from_canonical_u64(amount1 as u64);
    out[2] = F::from_canonical_u64(amount2 as u64);
    out[3] = F::from_canonical_u64(volume_fee_bps as u64);

    for j in 0..4 {
        out[4 + j] = F::from_canonical_u64(nullifier[j]);
    }
    for j in 0..4 {
        out[8 + j] = F::from_canonical_u64(exit1[j]);
    }
    for j in 0..4 {
        out[12 + j] = F::from_canonical_u64(exit2[j]);
    }
    for j in 0..4 {
        out[16 + j] = F::from_canonical_u64(block_hash[j]);
    }
    out[20] = F::from_canonical_u64(block_number as u64);
    let total_output = amount1 as u64 + amount2 as u64;
    let minimum_input = if total_output == 0 {
        0
    } else {
        assert!(volume_fee_bps < 10_000);
        total_output
            .checked_mul(10_000)
            .unwrap()
            .div_ceil(10_000 - volume_fee_bps as u64)
    };
    out[21] = F::from_canonical_u64(minimum_input);

    out
}

#[test]
fn make_leaf_pi_uses_supplied_fee() {
    let no_fee = make_leaf_pi(23, 0, 0, [0; 4], [0; 4], [0; 4], [0; 4], 0);
    assert_eq!(no_fee[VOLUME_FEE_BPS_INDEX].to_canonical_u64(), 0);
    assert_eq!(no_fee[INPUT_AMOUNT_INDEX].to_canonical_u64(), 23);

    let four_bps = make_leaf_pi(23, 0, 4, [0; 4], [0; 4], [0; 4], [0; 4], 0);
    assert_eq!(four_bps[VOLUME_FEE_BPS_INDEX].to_canonical_u64(), 4);
    assert_eq!(four_bps[INPUT_AMOUNT_INDEX].to_canonical_u64(), 24);
}

// ---------------- Private-batch proving helpers ----------------

/// Prove a private-batch aggregated proof using the monolithic PrivateBatchCircuit.
fn prove_private_batch_batch(
    private_batch_data: &CircuitData<F, C, D>,
    private_batch_targets: &PrivateBatchCircuitTargets,
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
) -> ProofWithPublicInputs<F, C, D> {
    assert_eq!(leaf_proofs.len(), NUM_LEAVES);

    let mut pw = PartialWitness::new();

    // NOTE: leaf_verifier_data is NOT set - it's baked in as constants

    // Fill each leaf proof target
    for (pt, proof) in private_batch_targets
        .leaf_proofs
        .iter()
        .zip(leaf_proofs.iter())
    {
        pw.set_proof_with_pis_target(pt, proof).unwrap();
    }

    // Dummy nullifier preimages: can be anything for non-dummy leaves (is_dummy=false), but must be filled.
    for (i, limbs) in private_batch_targets
        .dummy_nullifier_pre_images
        .iter()
        .enumerate()
    {
        for (j, t) in limbs.iter().enumerate() {
            let v = F::from_canonical_u64(1000 + (i as u64) * 10 + (j as u64));
            pw.set_target(*t, v).unwrap();
        }
    }

    // Identity nullifier permutation for deterministic public-batch fixtures.
    for switch in &private_batch_targets.nullifier_permutation_switches {
        pw.set_target(switch.target, F::ZERO).unwrap();
    }

    private_batch_data.prove(pw).unwrap()
}

// ---------------- Public-batch proving helpers ----------------

/// Prove a public-batch aggregated proof using PublicBatchCircuit.
fn prove_public_batch(
    public_batch_data: &CircuitData<F, C, D>,
    public_batch_targets: &PublicBatchCircuitTargets,
    private_batch_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    aggregator_address: [F; AGGREGATOR_ADDRESS_LEN],
) -> Result<ProofWithPublicInputs<F, C, D>, anyhow::Error> {
    assert_eq!(private_batch_proofs.len(), N_INNER);

    let mut pw = PartialWitness::new();

    // NOTE: private_batch_verifier_data is NOT set - it's baked in as constants

    // Fill private-batch proof targets
    for (pt, proof) in public_batch_targets
        .private_batch_proofs
        .iter()
        .zip(private_batch_proofs.iter())
    {
        pw.set_proof_with_pis_target(pt, proof).unwrap();
    }

    // Fill aggregator address (4 felts, 8 bytes/felt)
    for (i, limb) in aggregator_address.iter().enumerate() {
        pw.set_target(public_batch_targets.aggregator_address[i], *limb)
            .unwrap();
    }

    public_batch_data
        .prove(pw)
        .map_err(|e| anyhow::anyhow!("public_batch prove failed: {}", e))
}

// ---------------- Tests ----------------

/// Port of the old `two_layer_aggregation_pipeline` test, updated for:
/// - monolithic PrivateBatchCircuit
/// - monolithic PublicBatchCircuit
/// - aggregator_address is a witness target
#[test]
fn two_layer_aggregation_pipeline_monolithic() {
    let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
    let block_number = 42u32;

    // ---- 1) Build fake leaf circuit once and generate leaf proofs ----
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

    // Batch A: 2 leaf proofs
    let leaf_a0 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            100,
            0,
            TEST_VOLUME_FEE_BPS,
            [1, 2, 3, 4],
            [0, 0, 0, 0],
            [0x10, 0x11, 0x12, 0x13],
            block_hash,
            block_number,
        ),
    );
    let leaf_a1 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            200,
            50,
            TEST_VOLUME_FEE_BPS,
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [0x20, 0x21, 0x22, 0x23],
            block_hash,
            block_number,
        ),
    );

    // Batch B: 2 more leaf proofs (same leaf circuit, same block)
    let leaf_b0 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            300,
            0,
            TEST_VOLUME_FEE_BPS,
            [13, 14, 15, 16],
            [0, 0, 0, 0],
            [0x30, 0x31, 0x32, 0x33],
            block_hash,
            block_number,
        ),
    );
    let leaf_b1 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            400,
            100,
            TEST_VOLUME_FEE_BPS,
            [17, 18, 19, 20],
            [21, 22, 23, 24],
            [0x40, 0x41, 0x42, 0x43],
            block_hash,
            block_number,
        ),
    );

    // ---- 2) Build monolithic PrivateBatchCircuit once, prove two batches ----
    let leaf_common = leaf_data.common.clone();
    let leaf_verifier_only = leaf_data.verifier_only.clone();

    // SECURITY: leaf_verifier_only is baked in as constants at build time
    let private_batch_circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf_common,
        &leaf_verifier_only,
        NUM_LEAVES,
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    let private_batch_proof_a = prove_private_batch_batch(
        &private_batch_data,
        &private_batch_targets,
        vec![leaf_a0.clone(), leaf_a1.clone()],
    );
    let private_batch_proof_b = prove_private_batch_batch(
        &private_batch_data,
        &private_batch_targets,
        vec![leaf_b0.clone(), leaf_b1.clone()],
    );

    // Sanity: private-batch proofs verify under private-batch circuit data
    private_batch_data
        .verify(private_batch_proof_a.clone())
        .unwrap();
    private_batch_data
        .verify(private_batch_proof_b.clone())
        .unwrap();

    // ---- 3) Build monolithic PublicBatchCircuit and prove ----
    // SECURITY: private_batch_data.verifier_only is baked in as constants at build time
    let public_batch_circuit = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_data.common.clone(),
        &private_batch_data.verifier_only,
        N_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let public_batch_targets = public_batch_circuit.targets();
    let public_batch_data = public_batch_circuit.build_circuit();

    // 4 felts (8 bytes/felt) for hash-derived accounts
    let aggregator_address: [F; AGGREGATOR_ADDRESS_LEN] = [
        F::from_canonical_u64(0xDEAD),
        F::from_canonical_u64(0xBEEF),
        F::from_canonical_u64(0xCAFE),
        F::from_canonical_u64(0xBABE),
    ];

    let public_batch_proof = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![private_batch_proof_a.clone(), private_batch_proof_b.clone()],
        aggregator_address,
    )
    .expect("public-batch aggregation failed");

    // Verify proof
    public_batch_data
        .verify(public_batch_proof.clone())
        .expect("public-batch proof verification failed");

    // ---- 4) Verify output PIs match expected layout + forwarded content ----
    let pis = &public_batch_proof.public_inputs;

    // Expected PI length
    let expected_len = pbc::public_batch_pi_len(N_INNER, NUM_LEAVES);
    assert_eq!(pis.len(), expected_len, "unexpected public-batch PI length");

    // Aggregator address (4 felts, 8 bytes/felt)
    assert_eq!(
        pis[pbc::AGGREGATOR_ADDRESS_START].to_canonical_u64(),
        0xDEAD
    );
    assert_eq!(
        pis[pbc::AGGREGATOR_ADDRESS_START + 1].to_canonical_u64(),
        0xBEEF
    );
    assert_eq!(
        pis[pbc::AGGREGATOR_ADDRESS_START + 2].to_canonical_u64(),
        0xCAFE
    );
    assert_eq!(
        pis[pbc::AGGREGATOR_ADDRESS_START + 3].to_canonical_u64(),
        0xBABE
    );

    // Asset ID and volume fee
    assert_eq!(pis[pbc::ASSET_ID_START].to_canonical_u64(), 0); // asset_id = native
    assert_eq!(
        pis[pbc::VOLUME_FEE_BPS_START].to_canonical_u64(),
        TEST_VOLUME_FEE_BPS as u64
    );

    // Block hash
    assert_eq!(pis[pbc::BLOCK_HASH_START].to_canonical_u64(), 0xAA01);
    assert_eq!(pis[pbc::BLOCK_HASH_START + 1].to_canonical_u64(), 0xAA02);
    assert_eq!(pis[pbc::BLOCK_HASH_START + 2].to_canonical_u64(), 0xAA03);
    assert_eq!(pis[pbc::BLOCK_HASH_START + 3].to_canonical_u64(), 0xAA04);

    // Block number
    assert_eq!(pis[pbc::BLOCK_NUMBER_START].to_canonical_u64(), 42);

    // Total exit slots = N_INNER * (2 * NUM_LEAVES)
    assert_eq!(
        pis[pbc::TOTAL_EXIT_SLOTS_START].to_canonical_u64(),
        (N_INNER * 2 * NUM_LEAVES) as u64
    );

    // ---- Forwarding checks (exit slots + nullifiers) ----

    // public-batch exit slots region begins immediately after the header
    let public_batch_exit_start = pbc::PUBLIC_BATCH_HEADER_LEN;
    let private_batch_exit_start = pbc::private_batch_exit_slots_start();
    let private_batch_exit_len =
        pbc::private_batch_exit_slots_count(NUM_LEAVES) * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;

    // For each private-batch proof, ensure its exit slot region is copied verbatim into public-batch PIs.
    for (i, l0p) in [private_batch_proof_a.clone(), private_batch_proof_b.clone()]
        .into_iter()
        .enumerate()
    {
        let src = &l0p.public_inputs
            [private_batch_exit_start..private_batch_exit_start + private_batch_exit_len];
        let dst = &pis[public_batch_exit_start + i * private_batch_exit_len
            ..public_batch_exit_start + (i + 1) * private_batch_exit_len];
        assert_eq!(
            dst, src,
            "public-batch exit slots mismatch for inner proof {i}"
        );
    }

    // Nullifiers:
    let public_batch_null_start = pbc::public_batch_nullifiers_start(N_INNER, NUM_LEAVES);
    let private_batch_null_start = pbc::private_batch_nullifiers_start(NUM_LEAVES);
    let private_batch_null_len = pbc::private_batch_nullifiers_count(NUM_LEAVES) * 4;

    for (i, l0p) in [private_batch_proof_a, private_batch_proof_b]
        .into_iter()
        .enumerate()
    {
        let src = &l0p.public_inputs
            [private_batch_null_start..private_batch_null_start + private_batch_null_len];
        let dst = &pis[public_batch_null_start + i * private_batch_null_len
            ..public_batch_null_start + (i + 1) * private_batch_null_len];
        assert_eq!(
            dst, src,
            "public-batch nullifiers mismatch for inner proof {i}"
        );
    }
}

/// A partial public batch padded with an all-dummy private batch:
/// - proving succeeds (dummy exempt from consistency checks),
/// - header references come from the real inner proof,
/// - the dummy inner's exit slots AND nullifiers are zeroed in the output
///   (the private batch emits hash-of-preimage nullifiers for dummies, which
///   must NOT leak through to the chain).
#[test]
fn public_batch_with_dummy_padding() {
    let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
    let block_number = 42u32;

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

    // Real batch: 2 real leaves
    let real_0 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            100,
            0,
            TEST_VOLUME_FEE_BPS,
            [1, 2, 3, 4],
            [0, 0, 0, 0],
            [0x10, 0x11, 0x12, 0x13],
            block_hash,
            block_number,
        ),
    );
    let real_1 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            200,
            50,
            TEST_VOLUME_FEE_BPS,
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [0x20, 0x21, 0x22, 0x23],
            block_hash,
            block_number,
        ),
    );

    // Dummy batch: 2 dummy leaves (block_hash == 0 sentinel, zero amounts/exits)
    let dummy_leaf_pi = make_leaf_pi(0, 0, TEST_VOLUME_FEE_BPS, [0; 4], [0; 4], [0; 4], [0; 4], 0);
    let dummy_0 = prove_fake_leaf(&leaf_data, &leaf_targets, dummy_leaf_pi);
    let dummy_1 = prove_fake_leaf(&leaf_data, &leaf_targets, dummy_leaf_pi);

    let private_batch_circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        NUM_LEAVES,
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    let real_batch = prove_private_batch_batch(
        &private_batch_data,
        &private_batch_targets,
        vec![real_0, real_1],
    );
    let dummy_batch = prove_private_batch_batch(
        &private_batch_data,
        &private_batch_targets,
        vec![dummy_0, dummy_1],
    );

    // Sanity: the all-dummy private batch carries the dummy sentinel (block_hash == 0)
    // but NON-zero nullifiers (dummy replacement hashes) - exactly what the public
    // batch must zero out.
    let dummy_pis = &dummy_batch.public_inputs;
    for j in 0..4 {
        assert_eq!(
            dummy_pis[pbc::PRIVATE_BATCH_BLOCK_HASH_OFFSET + j].to_canonical_u64(),
            0,
            "all-dummy private batch must have block_hash == 0"
        );
    }
    let pb_null_start = pbc::private_batch_nullifiers_start(NUM_LEAVES);
    let pb_null_len = pbc::private_batch_nullifiers_count(NUM_LEAVES) * 4;
    assert!(
        dummy_pis[pb_null_start..pb_null_start + pb_null_len]
            .iter()
            .any(|f| f.to_canonical_u64() != 0),
        "dummy private batch is expected to emit non-zero replacement nullifiers"
    );

    let public_batch_circuit = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_data.common.clone(),
        &private_batch_data.verifier_only,
        N_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let public_batch_targets = public_batch_circuit.targets();
    let public_batch_data = public_batch_circuit.build_circuit();

    let aggregator_address: [F; AGGREGATOR_ADDRESS_LEN] = [
        F::from_canonical_u64(0xDEAD),
        F::from_canonical_u64(0xBEEF),
        F::from_canonical_u64(0xCAFE),
        F::from_canonical_u64(0xBABE),
    ];

    // Slot 0 = real batch, slot 1 = dummy padding
    let public_batch_proof = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![real_batch.clone(), dummy_batch],
        aggregator_address,
    )
    .expect("public batch with dummy padding must prove");

    public_batch_data
        .verify(public_batch_proof.clone())
        .expect("padded public-batch proof must verify");

    let pis = &public_batch_proof.public_inputs;

    // Header references come from the real (first non-dummy) inner
    assert_eq!(pis[pbc::ASSET_ID_START].to_canonical_u64(), 0);
    assert_eq!(
        pis[pbc::VOLUME_FEE_BPS_START].to_canonical_u64(),
        TEST_VOLUME_FEE_BPS as u64
    );
    for j in 0..4 {
        assert_eq!(
            pis[pbc::BLOCK_HASH_START + j].to_canonical_u64(),
            block_hash[j]
        );
    }
    assert_eq!(
        pis[pbc::BLOCK_NUMBER_START].to_canonical_u64(),
        block_number as u64
    );

    // Real inner's exit slots forwarded verbatim
    let exit_start = pbc::public_batch_exit_slots_start();
    let seg_exit_len =
        pbc::private_batch_exit_slots_count(NUM_LEAVES) * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
    let src_exit_start = pbc::private_batch_exit_slots_start();
    assert_eq!(
        &pis[exit_start..exit_start + seg_exit_len],
        &real_batch.public_inputs[src_exit_start..src_exit_start + seg_exit_len],
        "real inner's exit slots must be forwarded verbatim"
    );

    // Dummy inner's exit slots are all zero
    assert!(
        pis[exit_start + seg_exit_len..exit_start + 2 * seg_exit_len]
            .iter()
            .all(|f| f.to_canonical_u64() == 0),
        "dummy inner's exit slots must be zeroed"
    );

    // Real inner's nullifiers forwarded verbatim; dummy inner's zeroed
    let null_start = pbc::public_batch_nullifiers_start(N_INNER, NUM_LEAVES);
    let seg_null_len = pbc::private_batch_nullifiers_count(NUM_LEAVES) * 4;
    assert_eq!(
        &pis[null_start..null_start + seg_null_len],
        &real_batch.public_inputs[pb_null_start..pb_null_start + seg_null_len],
        "real inner's nullifiers must be forwarded verbatim"
    );
    assert!(
        pis[null_start + seg_null_len..null_start + 2 * seg_null_len]
            .iter()
            .all(|f| f.to_canonical_u64() == 0),
        "dummy inner's nullifiers must be zeroed"
    );
}

/// Negative test: if two private-batch proofs use different block hashes, public-batch proving must fail.
#[test]
fn public_batch_mismatched_blocks_fails() {
    let block_a: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
    let block_b: [u64; 4] = [0xBB01, 0xBB02, 0xBB03, 0xBB04];
    let block_number = 42u32;

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

    // Batch A uses block_a
    let a0 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            100,
            0,
            TEST_VOLUME_FEE_BPS,
            [1, 2, 3, 4],
            [0, 0, 0, 0],
            [1, 2, 3, 4],
            block_a,
            block_number,
        ),
    );
    let a1 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            200,
            0,
            TEST_VOLUME_FEE_BPS,
            [5, 6, 7, 8],
            [0, 0, 0, 0],
            [5, 6, 7, 8],
            block_a,
            block_number,
        ),
    );

    // Batch B uses block_b (still internally consistent)
    let b0 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            300,
            0,
            TEST_VOLUME_FEE_BPS,
            [9, 10, 11, 12],
            [0, 0, 0, 0],
            [9, 10, 11, 12],
            block_b,
            block_number,
        ),
    );
    let b1 = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            400,
            0,
            TEST_VOLUME_FEE_BPS,
            [13, 14, 15, 16],
            [0, 0, 0, 0],
            [13, 14, 15, 16],
            block_b,
            block_number,
        ),
    );

    // Private-batch circuit
    // SECURITY: leaf verifier_only is baked in as constants at build time
    let private_batch_circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        NUM_LEAVES,
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    let private_batch_a =
        prove_private_batch_batch(&private_batch_data, &private_batch_targets, vec![a0, a1]);
    let private_batch_b =
        prove_private_batch_batch(&private_batch_data, &private_batch_targets, vec![b0, b1]);

    // Public-batch circuit
    // SECURITY: l0 verifier_only is baked in as constants at build time
    let public_batch_circuit = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_data.common.clone(),
        &private_batch_data.verifier_only,
        N_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let public_batch_targets = public_batch_circuit.targets();
    let public_batch_data = public_batch_circuit.build_circuit();

    let agg_addr = [
        F::from_canonical_u64(1),
        F::from_canonical_u64(2),
        F::from_canonical_u64(3),
        F::from_canonical_u64(4),
    ];

    let res = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![private_batch_a, private_batch_b],
        agg_addr,
    );

    assert!(
        res.is_err(),
        "expected public-batch proving to fail for mismatched blocks"
    );
}

#[test]
fn public_batch_enforces_asset_and_fee_consistency() {
    let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
    let block_number = 42u32;
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

    let private_batch_circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        NUM_LEAVES,
    )
    .unwrap();
    let private_batch_targets = private_batch_circuit.targets();
    let private_batch_data = private_batch_circuit.build_circuit();

    let public_batch_circuit = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_data.common.clone(),
        &private_batch_data.verifier_only,
        N_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let public_batch_targets = public_batch_circuit.targets();
    let public_batch_data = public_batch_circuit.build_circuit();

    let prove_inner = |asset_id: u32, fee_bps: u32, seed: u64| {
        let leaves = (0..NUM_LEAVES)
            .map(|i| {
                let n = seed + i as u64;
                prove_fake_leaf(
                    &leaf_data,
                    &leaf_targets,
                    make_leaf_pi_with_asset(
                        asset_id,
                        100 + i as u32,
                        0,
                        fee_bps,
                        [n + 1, n + 2, n + 3, n + 4],
                        [0; 4],
                        [n + 101, n + 102, n + 103, n + 104],
                        block_hash,
                        block_number,
                    ),
                )
            })
            .collect();
        prove_private_batch_batch(&private_batch_data, &private_batch_targets, leaves)
    };
    let aggregator_address = [
        F::from_canonical_u64(1),
        F::from_canonical_u64(2),
        F::from_canonical_u64(3),
        F::from_canonical_u64(4),
    ];

    let base = prove_inner(0, TEST_VOLUME_FEE_BPS, 1_000);
    let different_asset = prove_inner(1, TEST_VOLUME_FEE_BPS, 2_000);
    assert!(
        prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![base.clone(), different_asset],
            aggregator_address,
        )
        .is_err(),
        "public-batch proving must reject mismatched asset IDs"
    );

    let different_fee = prove_inner(0, TEST_VOLUME_FEE_BPS + 1, 3_000);
    assert!(
        prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![base, different_fee],
            aggregator_address,
        )
        .is_err(),
        "public-batch proving must reject mismatched fee rates"
    );

    let fee_four_a = prove_inner(0, 4, 4_000);
    let fee_four_b = prove_inner(0, 4, 5_000);
    let proof = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![fee_four_a, fee_four_b],
        aggregator_address,
    )
    .expect("matching non-default fees must aggregate");
    assert_eq!(
        proof.public_inputs[pbc::VOLUME_FEE_BPS_START].to_canonical_u64(),
        4,
        "public-batch output must forward the actual segment fee rate"
    );
}

/// Public-batch equivalent of the private-batch verifier-key-substitution
/// test: the private-batch verifier key is baked into the public-batch
/// circuit as constants, so a structurally identical private-batch proof
/// produced by a DIFFERENT circuit — here, a private batch aggregating a
/// shape-identical leaf circuit with different range-check wiring — must be rejected at prove time. Without
/// the constant VK, an attacker could launder arbitrary leaf claims (no
/// fee check, fabricated amounts) through a legit-shaped private batch.
#[test]
fn public_batch_rejects_proofs_from_substituted_private_batch_circuit() {
    let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
    let block_number = 42u32;

    // ---- Legit pipeline: leaf VK -> private batch VK -> public batch ----
    let (leaf_data, _leaf_targets) = build_fake_leaf_circuit();
    let legit_private_batch = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf_data.common,
        &leaf_data.verifier_only,
        NUM_LEAVES,
    )
    .unwrap();
    let legit_private_batch_data = legit_private_batch.build_circuit();

    // SECURITY: the LEGIT private-batch verifier key is baked in here.
    let public_batch_circuit = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        legit_private_batch_data.common.clone(),
        &legit_private_batch_data.verifier_only,
        N_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let public_batch_targets = public_batch_circuit.targets();
    let public_batch_data = public_batch_circuit.build_circuit();

    // ---- Attacker pipeline: weaker leaf, same PI and common-data shape ----
    let (malicious_leaf_data, malicious_leaf_targets) = {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let pis: Vec<Target> = (0..LEAF_PI_LEN)
            .map(|_| builder.add_virtual_target())
            .collect();
        // Match the legitimate fake leaf's four 32-bit checks, but wire the
        // fourth check to asset_id instead of input_amount. This preserves
        // CommonCircuitData while changing the verifier key and leaves the
        // claimed input amount unconstrained.
        for index in [0, 1, 2, 3] {
            builder.range_check(pis[index], 32);
        }
        builder.register_public_inputs(&pis);
        (builder.build::<C>(), pis)
    };
    let malicious_private_batch = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &malicious_leaf_data.common,
        &malicious_leaf_data.verifier_only,
        NUM_LEAVES,
    )
    .unwrap();
    let malicious_pb_targets = malicious_private_batch.targets();
    let malicious_pb_data = malicious_private_batch.build_circuit();

    // "Valid-looking" leaves the legit leaf circuit would never have proved
    // (no Merkle binding or aggregate-fee provenance applies to these values).
    let malicious_leaves: Vec<ProofWithPublicInputs<F, C, D>> = (0..NUM_LEAVES)
        .map(|i| {
            let n = i as u64 + 1;
            let pi = make_leaf_pi(
                1_000_000,
                0,
                TEST_VOLUME_FEE_BPS,
                [90 + n, 91, 92, 93],
                [0, 0, 0, 0],
                [70 + n, 71, 72, 73],
                block_hash,
                block_number,
            );
            let mut pw = PartialWitness::new();
            for (t, v) in malicious_leaf_targets.iter().zip(pi.iter()) {
                pw.set_target(*t, *v).unwrap();
            }
            malicious_leaf_data.prove(pw).unwrap()
        })
        .collect();

    let malicious_pb_proof =
        prove_private_batch_batch(&malicious_pb_data, &malicious_pb_targets, malicious_leaves);
    // Sanity: the forged proof verifies under the ATTACKER's circuit...
    malicious_pb_data
        .verify(malicious_pb_proof.clone())
        .expect("forged proof must verify under the attacker's own circuit");

    // ...but the public batch, with the legit VK baked in, must reject it
    // (either at witness assignment on shape mismatch or at prove time on
    // the constant verifier-key constraints).
    // Precondition: the two private-batch circuits differ ONLY in the baked
    // leaf verifier-key constants, so their proof shapes are identical. The
    // forged proof therefore reaches the circuit, and the rejection below
    // is enforced by the constant verifier-key constraints — not by some
    // incidental shape mismatch.
    let gate_serializer = plonky2::util::serialization::DefaultGateSerializer;
    assert_eq!(
        malicious_pb_data.common.to_bytes(&gate_serializer).unwrap(),
        legit_private_batch_data
            .common
            .to_bytes(&gate_serializer)
            .unwrap(),
        "test precondition: forged proof must be shape-identical to legit proofs"
    );

    // plonky2 surfaces the constraint violation as an Err or a panic
    // depending on where witness generation contradicts; both are rejections.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![malicious_pb_proof.clone(), malicious_pb_proof],
            [
                F::from_canonical_u64(1),
                F::from_canonical_u64(2),
                F::from_canonical_u64(3),
                F::from_canonical_u64(4),
            ],
        )
    }));
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "public batch must reject private-batch proofs from a substituted circuit"
    );
}
