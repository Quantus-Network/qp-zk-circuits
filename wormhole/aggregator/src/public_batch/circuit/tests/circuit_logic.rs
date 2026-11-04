use super::*;
use plonky2::field::types::PrimeField64;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{
    BytesDigest, WithdrawalOutput, ASSET_ID_INDEX, BLOCK_HASH_START_INDEX, BLOCK_NUMBER_INDEX,
    INPUT_AMOUNT_INDEX, NULLIFIER_START_INDEX, PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN,
};

use super::super::constants::AGGREGATOR_ADDRESS_LEN;
use crate::private_batch::circuit::circuit_logic::{
    PrivateBatchCircuit, PrivateBatchCircuitTargets,
};
use crate::private_batch::prover::witness::fill_private_batch_witness;
use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

const NUM_LEAVES: usize = 2; // 2 leaf proofs per private batch (fast)
const INNER_SHAPE: PrivateBatchShape = PrivateBatchShape::new(NUM_LEAVES, 3);
const N_INNER: usize = 2; // 2 private-batch proofs aggregated into one public-batch proof
const TEST_VOLUME_FEE_BPS: u32 = 10;
const BLOCK_NUMBER: u32 = 42;
const BLOCK_A: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
const BLOCK_B: [u64; 4] = [0xBB01, 0xBB02, 0xBB03, 0xBB04];

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

    let shape = PrivateBatchShape::new(1, 1);
    let (leaf, _) = build_fake_leaf_circuit();
    let private_batch = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        shape,
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
            shape,
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
        shape,
    )
    .err()
    .expect("oversized rate_bits must be rejected before construction");
    assert!(err.to_string().contains("rate_bits"), "got: {err}");
}

/// The public batch indexes fixed offsets derived from the private-batch
/// shape, so an inner circuit whose PI length belongs to a different shape
/// must be rejected before construction.
#[test]
fn new_rejects_inner_circuit_with_mismatched_shape() {
    let (leaf, _) = build_fake_leaf_circuit();
    let private_batch = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        PrivateBatchShape::new(1, 2),
    )
    .unwrap()
    .build_verifier();

    let err = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch.common.clone(),
        &private_batch.verifier_only,
        1,
        PrivateBatchShape::new(1, 1),
    )
    .err()
    .expect("shape mismatch must be rejected");
    assert!(err.to_string().contains("num_public_inputs"), "got: {err}");
}

// ---------------- Leaf PI helpers ----------------

fn make_leaf_pi(
    input_amount: u32,
    nullifier: [u64; 4],
    block_hash: [u64; 4],
    block_number: u32,
) -> [F; LEAF_PI_LEN] {
    make_leaf_pi_with_asset(0, input_amount, nullifier, block_hash, block_number)
}

fn make_leaf_pi_with_asset(
    asset_id: u32,
    input_amount: u32,
    nullifier: [u64; 4],
    block_hash: [u64; 4],
    block_number: u32,
) -> [F; LEAF_PI_LEN] {
    let mut out = [F::ZERO; LEAF_PI_LEN];
    out[ASSET_ID_INDEX] = F::from_canonical_u64(asset_id as u64);
    for j in 0..4 {
        out[NULLIFIER_START_INDEX + j] = F::from_canonical_u64(nullifier[j]);
        out[BLOCK_HASH_START_INDEX + j] = F::from_canonical_u64(block_hash[j]);
    }
    out[BLOCK_NUMBER_INDEX] = F::from_canonical_u64(block_number as u64);
    out[INPUT_AMOUNT_INDEX] = F::from_canonical_u64(input_amount as u64);
    out
}

fn output(account: u8, amount: u32) -> WithdrawalOutput {
    WithdrawalOutput {
        exit_account: BytesDigest::try_from([0x10 + account; 32]).unwrap(),
        amount,
    }
}

// ---------------- Private-batch proving helpers ----------------

fn build_private_batch(
    leaf: &CircuitData<F, C, D>,
) -> (CircuitData<F, C, D>, PrivateBatchCircuitTargets) {
    let circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        &leaf.common,
        &leaf.verifier_only,
        INNER_SHAPE,
    )
    .unwrap();
    let targets = circuit.targets();
    (circuit.build_circuit(), targets)
}

/// Prove a private-batch aggregated proof using the monolithic PrivateBatchCircuit
/// (identity nullifier permutation, deterministic dummy preimages).
fn prove_private_batch_batch(
    private_batch_data: &CircuitData<F, C, D>,
    private_batch_targets: &PrivateBatchCircuitTargets,
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    outputs: &[WithdrawalOutput],
    volume_fee_bps: u32,
) -> ProofWithPublicInputs<F, C, D> {
    assert_eq!(leaf_proofs.len(), NUM_LEAVES);
    let mut padded_outputs = outputs.to_vec();
    padded_outputs.resize(INNER_SHAPE.num_exit_slots, WithdrawalOutput::default());
    let pre_images: Vec<[F; 4]> = (0..NUM_LEAVES)
        .map(|i| core::array::from_fn(|j| F::from_canonical_u64(1000 + (i as u64) * 10 + j as u64)))
        .collect();

    let mut pw = PartialWitness::new();
    fill_private_batch_witness(
        &mut pw,
        private_batch_targets,
        &leaf_proofs,
        &padded_outputs,
        volume_fee_bps,
        &pre_images,
        &(0..NUM_LEAVES).collect::<Vec<_>>(),
    )
    .unwrap();
    private_batch_data.prove(pw).unwrap()
}

/// A private batch of `NUM_LEAVES` real leaves at `block`, each burning
/// `input_amount`, paying `outputs` at `fee_bps`. `seed` derives distinct
/// nullifiers.
#[allow(clippy::too_many_arguments)]
fn prove_inner(
    leaf_data: &CircuitData<F, C, D>,
    leaf_targets: &[Target; LEAF_PI_LEN],
    private_batch: &(CircuitData<F, C, D>, PrivateBatchCircuitTargets),
    asset_id: u32,
    input_amount: u32,
    block_hash: [u64; 4],
    seed: u64,
    outputs: &[WithdrawalOutput],
    fee_bps: u32,
) -> ProofWithPublicInputs<F, C, D> {
    let leaves = (0..NUM_LEAVES)
        .map(|i| {
            let n = seed + i as u64;
            prove_fake_leaf(
                leaf_data,
                leaf_targets,
                make_leaf_pi_with_asset(
                    asset_id,
                    input_amount,
                    [n + 101, n + 102, n + 103, n + 104],
                    block_hash,
                    BLOCK_NUMBER,
                ),
            )
        })
        .collect();
    prove_private_batch_batch(&private_batch.0, &private_batch.1, leaves, outputs, fee_bps)
}

// ---------------- Public-batch proving helpers ----------------

fn build_public_batch(
    private_batch_data: &CircuitData<F, C, D>,
) -> (CircuitData<F, C, D>, PublicBatchCircuitTargets) {
    let circuit = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_data.common.clone(),
        &private_batch_data.verifier_only,
        N_INNER,
        INNER_SHAPE,
    )
    .unwrap();
    let targets = circuit.targets();
    (circuit.build_circuit(), targets)
}

const AGGREGATOR_ADDRESS: [u64; 4] = [0xDEAD, 0xBEEF, 0xCAFE, 0xBABE];

/// Prove a public-batch aggregated proof using PublicBatchCircuit.
fn prove_public_batch(
    public_batch_data: &CircuitData<F, C, D>,
    public_batch_targets: &PublicBatchCircuitTargets,
    private_batch_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
) -> Result<ProofWithPublicInputs<F, C, D>, anyhow::Error> {
    assert_eq!(private_batch_proofs.len(), N_INNER);

    let mut pw = PartialWitness::new();
    for (pt, proof) in public_batch_targets
        .private_batch_proofs
        .iter()
        .zip(private_batch_proofs.iter())
    {
        pw.set_proof_with_pis_target(pt, proof).unwrap();
    }
    for (i, limb) in AGGREGATOR_ADDRESS.iter().enumerate() {
        pw.set_target(
            public_batch_targets.aggregator_address[i],
            F::from_canonical_u64(*limb),
        )
        .unwrap();
    }

    public_batch_data
        .prove(pw)
        .map_err(|e| anyhow::anyhow!("public_batch prove failed: {}", e))
}

fn exit_segment(pis: &[F], i: usize) -> &[F] {
    let seg_len =
        pbc::private_batch_exit_slots_count(INNER_SHAPE) * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
    let start = pbc::public_batch_exit_slots_start() + i * seg_len;
    &pis[start..start + seg_len]
}

fn nullifier_segment(pis: &[F], i: usize) -> &[F] {
    let seg_len = pbc::private_batch_nullifiers_count(INNER_SHAPE) * 4;
    let start = pbc::public_batch_nullifiers_start(N_INNER, INNER_SHAPE) + i * seg_len;
    &pis[start..start + seg_len]
}

fn inner_exit_region(pis: &[F]) -> &[F] {
    let start = pbc::private_batch_exit_slots_start();
    let len = pbc::private_batch_exit_slots_count(INNER_SHAPE) * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
    &pis[start..start + len]
}

fn inner_nullifier_region(pis: &[F]) -> &[F] {
    let start = pbc::private_batch_nullifiers_start(INNER_SHAPE);
    let len = pbc::private_batch_nullifiers_count(INNER_SHAPE) * 4;
    &pis[start..start + len]
}

// ---------------- Tests ----------------

#[test]
fn two_layer_aggregation_pipeline_monolithic() {
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let private_batch = build_private_batch(&leaf_data);

    let inner_a = prove_inner(
        &leaf_data,
        &leaf_targets,
        &private_batch,
        0,
        1_000,
        BLOCK_A,
        1_000,
        &[output(1, 1_500), output(2, 400)],
        TEST_VOLUME_FEE_BPS,
    );
    let inner_b = prove_inner(
        &leaf_data,
        &leaf_targets,
        &private_batch,
        0,
        2_000,
        BLOCK_A,
        2_000,
        &[output(3, 3_000), output(4, 500), output(5, 496)],
        TEST_VOLUME_FEE_BPS,
    );
    private_batch.0.verify(inner_a.clone()).unwrap();
    private_batch.0.verify(inner_b.clone()).unwrap();

    let (public_batch_data, public_batch_targets) = build_public_batch(&private_batch.0);
    let public_batch_proof = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![inner_a.clone(), inner_b.clone()],
    )
    .expect("public-batch aggregation failed");
    public_batch_data
        .verify(public_batch_proof.clone())
        .expect("public-batch proof verification failed");

    let pis = &public_batch_proof.public_inputs;
    assert_eq!(pis.len(), pbc::public_batch_pi_len(N_INNER, INNER_SHAPE));

    for (j, limb) in AGGREGATOR_ADDRESS.iter().enumerate() {
        assert_eq!(
            pis[pbc::AGGREGATOR_ADDRESS_START + j].to_canonical_u64(),
            *limb
        );
    }
    assert_eq!(pis[pbc::ASSET_ID_START].to_canonical_u64(), 0);
    assert_eq!(
        pis[pbc::VOLUME_FEE_BPS_START].to_canonical_u64(),
        TEST_VOLUME_FEE_BPS as u64
    );
    for j in 0..4 {
        assert_eq!(
            pis[pbc::BLOCK_HASH_START + j].to_canonical_u64(),
            BLOCK_A[j]
        );
    }
    assert_eq!(
        pis[pbc::BLOCK_NUMBER_START].to_canonical_u64(),
        BLOCK_NUMBER as u64
    );
    assert_eq!(
        pis[pbc::TOTAL_EXIT_SLOTS_START].to_canonical_u64(),
        (N_INNER * INNER_SHAPE.num_exit_slots) as u64
    );

    for (i, inner) in [inner_a, inner_b].iter().enumerate() {
        assert_eq!(
            exit_segment(pis, i),
            inner_exit_region(&inner.public_inputs),
            "public-batch exit slots mismatch for inner proof {i}"
        );
        assert_eq!(
            nullifier_segment(pis, i),
            inner_nullifier_region(&inner.public_inputs),
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
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let private_batch = build_private_batch(&leaf_data);

    let real_batch = prove_inner(
        &leaf_data,
        &leaf_targets,
        &private_batch,
        0,
        1_000,
        BLOCK_A,
        1_000,
        &[output(1, 1_500), output(2, 400)],
        TEST_VOLUME_FEE_BPS,
    );
    let dummy_leaf_pi = make_leaf_pi(0, [0; 4], [0; 4], 0);
    let dummy_batch = prove_private_batch_batch(
        &private_batch.0,
        &private_batch.1,
        vec![
            prove_fake_leaf(&leaf_data, &leaf_targets, dummy_leaf_pi),
            prove_fake_leaf(&leaf_data, &leaf_targets, dummy_leaf_pi),
        ],
        &[],
        0,
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
    assert!(
        inner_nullifier_region(dummy_pis)
            .iter()
            .any(|f| f.to_canonical_u64() != 0),
        "dummy private batch is expected to emit non-zero replacement nullifiers"
    );

    let (public_batch_data, public_batch_targets) = build_public_batch(&private_batch.0);

    // Slot 0 = real batch, slot 1 = dummy padding
    let public_batch_proof = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![real_batch.clone(), dummy_batch],
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
            BLOCK_A[j]
        );
    }
    assert_eq!(
        pis[pbc::BLOCK_NUMBER_START].to_canonical_u64(),
        BLOCK_NUMBER as u64
    );

    assert_eq!(
        exit_segment(pis, 0),
        inner_exit_region(&real_batch.public_inputs),
        "real inner's exit slots must be forwarded verbatim"
    );
    assert!(
        exit_segment(pis, 1)
            .iter()
            .all(|f| f.to_canonical_u64() == 0),
        "dummy inner's exit slots must be zeroed"
    );
    assert_eq!(
        nullifier_segment(pis, 0),
        inner_nullifier_region(&real_batch.public_inputs),
        "real inner's nullifiers must be forwarded verbatim"
    );
    assert!(
        nullifier_segment(pis, 1)
            .iter()
            .all(|f| f.to_canonical_u64() == 0),
        "dummy inner's nullifiers must be zeroed"
    );
}

/// Negative test: if two private-batch proofs use different block hashes, public-batch proving must fail.
#[test]
fn public_batch_mismatched_blocks_fails() {
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let private_batch = build_private_batch(&leaf_data);

    let inner_a = prove_inner(
        &leaf_data,
        &leaf_targets,
        &private_batch,
        0,
        100,
        BLOCK_A,
        1_000,
        &[],
        TEST_VOLUME_FEE_BPS,
    );
    let inner_b = prove_inner(
        &leaf_data,
        &leaf_targets,
        &private_batch,
        0,
        100,
        BLOCK_B,
        2_000,
        &[],
        TEST_VOLUME_FEE_BPS,
    );

    let (public_batch_data, public_batch_targets) = build_public_batch(&private_batch.0);
    assert!(
        prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![inner_a, inner_b]
        )
        .is_err(),
        "expected public-batch proving to fail for mismatched blocks"
    );
}

#[test]
fn public_batch_enforces_asset_and_fee_consistency() {
    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let private_batch = build_private_batch(&leaf_data);
    let (public_batch_data, public_batch_targets) = build_public_batch(&private_batch.0);

    let inner = |asset_id: u32, fee_bps: u32, seed: u64| {
        prove_inner(
            &leaf_data,
            &leaf_targets,
            &private_batch,
            asset_id,
            100,
            BLOCK_A,
            seed,
            &[],
            fee_bps,
        )
    };

    let base = inner(0, TEST_VOLUME_FEE_BPS, 1_000);
    let different_asset = inner(1, TEST_VOLUME_FEE_BPS, 2_000);
    assert!(
        prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![base.clone(), different_asset],
        )
        .is_err(),
        "public-batch proving must reject mismatched asset IDs"
    );

    let different_fee = inner(0, TEST_VOLUME_FEE_BPS + 1, 3_000);
    assert!(
        prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![base, different_fee]
        )
        .is_err(),
        "public-batch proving must reject mismatched fee rates"
    );

    let fee_four_a = inner(0, 4, 4_000);
    let fee_four_b = inner(0, 4, 5_000);
    let proof = prove_public_batch(
        &public_batch_data,
        &public_batch_targets,
        vec![fee_four_a, fee_four_b],
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
    // ---- Legit pipeline: leaf VK -> private batch VK -> public batch ----
    let (leaf_data, _leaf_targets) = build_fake_leaf_circuit();
    let legit_private_batch = build_private_batch(&leaf_data);
    let (public_batch_data, public_batch_targets) = build_public_batch(&legit_private_batch.0);

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
    let malicious_private_batch = build_private_batch(&malicious_leaf_data);

    // "Valid-looking" leaves the legit leaf circuit would never have proved
    // (no Merkle binding applies to these values).
    let malicious_leaves: Vec<ProofWithPublicInputs<F, C, D>> = (0..NUM_LEAVES)
        .map(|i| {
            let n = i as u64 + 1;
            let pi = make_leaf_pi(1_000_000, [70 + n, 71, 72, 73], BLOCK_A, BLOCK_NUMBER);
            let mut pw = PartialWitness::new();
            for (t, v) in malicious_leaf_targets.iter().zip(pi.iter()) {
                pw.set_target(*t, *v).unwrap();
            }
            malicious_leaf_data.prove(pw).unwrap()
        })
        .collect();

    let malicious_pb_proof = prove_private_batch_batch(
        &malicious_private_batch.0,
        &malicious_private_batch.1,
        malicious_leaves,
        &[output(1, 1_990_000)],
        TEST_VOLUME_FEE_BPS,
    );
    // Sanity: the forged proof verifies under the ATTACKER's circuit...
    malicious_private_batch
        .0
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
        malicious_private_batch
            .0
            .common
            .to_bytes(&gate_serializer)
            .unwrap(),
        legit_private_batch
            .0
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
        )
    }));
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "public batch must reject private-batch proofs from a substituted circuit"
    );
}

/// Records the `n_inner` public-batch wrapper over `TRACED_INNER_SHAPE` private batches —
/// the wrapper logic only, on virtual inner-proof PI targets, without the recursive
/// verifiers — for the Lean constraint exporter (`qp-plonky2/constraint-exporter`,
/// PLAN.md Step 8) and checks the trace `formal/traces/public_batch_wrapper_n{n_inner}.json`
/// is current. Regenerate with `UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-aggregator
/// --lib public_batch_wrapper_n`.
fn check_public_batch_wrapper_trace(n_inner: usize) {
    use zk_circuits_common::circuit::wormhole_public_batch_circuit_config;
    use zk_circuits_common::formal_trace::{Trace, TracingBuilder};

    // Matches the shape the private-batch wrapper trace is recorded at.
    const TRACED_INNER_SHAPE: PrivateBatchShape = PrivateBatchShape::new(2, 2);

    let leaf = build_fake_leaf_circuit().0;
    let mut tracing = TracingBuilder::new(wormhole_public_batch_circuit_config());

    // Only the PI slice of each inner proof is read by the wrapper; the proof body comes
    // from any common data. Where production runs `add_recursive_verifiers` under the
    // `TRACED_INNER_SHAPE` private-batch verifier key.
    let pi_len = pbc::private_batch_pi_len(TRACED_INNER_SHAPE);
    let child = format!(
        "private_batch_wrapper_n{}",
        TRACED_INNER_SHAPE.num_leaf_proofs
    );
    let private_batch_proofs: Vec<_> = (0..n_inner)
        .map(|_| {
            let mut proof = tracing.inner.add_virtual_proof_with_pis(&leaf.common);
            proof.public_inputs = tracing.inner.add_virtual_targets(pi_len);
            tracing.verify_proof(&child, &proof);
            proof
        })
        .collect();
    let aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN] = tracing
        .inner
        .add_virtual_targets(AGGREGATOR_ADDRESS_LEN)
        .try_into()
        .unwrap();
    let rows_before = tracing.inner.num_gates();
    let targets = PublicBatchCircuitTargets {
        private_batch_proofs,
        aggregator_address,
    };
    super::build_public_batch_constraints(&mut tracing, &targets, n_inner, TRACED_INNER_SHAPE);
    assert_eq!(
        rows_before, 0,
        "wrapper rows must start at 0 for the exporter"
    );

    let mut named = Vec::new();
    for (i, proof) in targets.private_batch_proofs.iter().enumerate() {
        named.push((format!("inner_pis_{i}"), proof.public_inputs.clone()));
    }
    named.push((
        "aggregator_address".to_string(),
        targets.aggregator_address.to_vec(),
    ));
    let name = format!("public_batch_wrapper_n{n_inner}");
    let trace = tracing.trace(&name, named);
    let json = trace.to_json();
    let round_trip = Trace::from_json(&json).expect("trace round-trips");
    assert_eq!(round_trip.to_json(), json);
    println!(
        "public wrapper trace n_inner={n_inner} inner={TRACED_INNER_SHAPE:?}: rows={} copies={} calls={}",
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
         public_batch_wrapper_n"
    );
}

#[test]
fn public_batch_wrapper_n2_trace_is_current() {
    check_public_batch_wrapper_trace(2);
}

#[test]
fn public_batch_wrapper_n4_trace_is_current() {
    check_public_batch_wrapper_trace(4);
}
