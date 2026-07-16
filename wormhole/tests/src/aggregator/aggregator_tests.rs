#![cfg(test)]

use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{BytesDigest, PublicCircuitInputs};
use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};
use test_helpers::{compute_zk_leaf_hash, TestInputs};
use wormhole_aggregator::aggregator::PublicBatchAggregator;
use wormhole_aggregator::pool::BatchKey;
use wormhole_aggregator::common::utils::{
    load_canonical_leaf_verifier_data, load_canonical_private_batch_verifier_data,
};
use wormhole_aggregator::private_batch::prover::PrivateBatchProver;
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};

use crate::aggregator::circuit_config;

/// Leaves per private batch in the client-side test artifacts.
const PRIVATE_NUM_LEAVES: usize = 2;

static TEST_INIT: Once = Once::new();
static PUBLIC_TEST_INIT: Once = Once::new();

/// Absolute per-process root for generated circuit artifacts.
///
/// Tests previously used cwd-relative directories, which made every test in
/// the binary sensitive to the working directory and to sibling tests'
/// cleanup. Absolute paths keyed by pid keep parallel test binaries and
/// reruns isolated from each other.
fn test_bins_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::temp_dir().join(format!(
            "qp-wormhole-aggregator-tests-{}",
            std::process::id()
        ))
    })
}

fn private_bins_dir() -> PathBuf {
    test_bins_root().join("private")
}

fn public_bins_dir() -> PathBuf {
    test_bins_root().join("public")
}

extern "C" fn cleanup_test_bins_root() {
    // Best-effort cleanup (don't panic during shutdown).
    let _ = std::fs::remove_dir_all(test_bins_root());
}

fn setup_test_binaries() {
    TEST_INIT.call_once(|| {
        generate_all_circuit_binaries(private_bins_dir(), true, PRIVATE_NUM_LEAVES, None)
            .expect("Failed to generate test circuit binaries");

        // Register a process-exit cleanup so the directory is removed once all tests finish.
        unsafe {
            // Ignore return value; if registration fails we simply won't auto-clean.
            let _ = libc::atexit(cleanup_test_bins_root);
        }
    });
}

fn setup_public_test_binaries() {
    PUBLIC_TEST_INIT.call_once(|| {
        // Smallest public-batch circuit (1 inner private-batch of 1 leaf) to keep
        // artifact generation fast.
        generate_all_circuit_binaries(public_bins_dir(), true, 1, Some(1))
            .expect("Failed to generate public-batch test circuit binaries");

        unsafe {
            let _ = libc::atexit(cleanup_test_bins_root);
        }
    });
}

fn make_leaf_proof_in(dir: &Path, inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    let prover = WormholeProver::new_from_files(&dir.join("prover.bin"), &dir.join("common.bin"))
        .expect("Failed to create prover from binaries");
    prover.commit(inputs).unwrap().prove().unwrap()
}

fn make_leaf_proof(inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    setup_test_binaries();
    make_leaf_proof_in(&private_bins_dir(), inputs)
}

fn make_private_batch_prover() -> PrivateBatchProver {
    setup_test_binaries();
    PrivateBatchProver::new_from_binaries_dir(&private_bins_dir())
        .expect("Failed to load private-batch prover from generated binaries")
}

/// Canonical-pinned verifier for the client-side private-batch artifacts.
fn private_batch_verifier() -> VerifierCircuitData<F, C, D> {
    setup_test_binaries();
    let dir = private_bins_dir();
    let leaf = load_canonical_leaf_verifier_data(
        &std::fs::read(dir.join("common.bin")).unwrap(),
        &std::fs::read(dir.join("verifier.bin")).unwrap(),
    )
    .expect("Failed to load leaf verifier data");
    load_canonical_private_batch_verifier_data(
        &std::fs::read(dir.join("private_batch_common.bin")).unwrap(),
        &std::fs::read(dir.join("private_batch_verifier.bin")).unwrap(),
        &leaf,
        PRIVATE_NUM_LEAVES,
    )
    .expect("Failed to load private-batch verifier data")
}

/// Valid leaf inputs like `test_inputs_0` but with a REAL block hash computed
/// from the header fields, so the proof is non-dummy (`test_inputs_0` uses the
/// dummy sentinel `block_hash == 0`, which pools into the dummy bucket that
/// `PublicBatchAggregator` refuses to aggregate).
fn test_inputs_with_real_block() -> CircuitInputs {
    use wormhole_circuit::block_header::header::HeaderInputs;

    let mut inputs = CircuitInputs::test_inputs_0();
    inputs.public.block_hash = HeaderInputs::try_from(&inputs)
        .expect("header inputs from test inputs")
        .block_hash();
    inputs
}

/// Valid leaf inputs like `test_inputs_0` but for a non-native asset. The asset
/// id is part of the ZK leaf hash, so the tree root must be recomputed.
fn test_inputs_with_asset(asset_id: u32) -> CircuitInputs {
    let mut inputs = CircuitInputs::test_inputs_0();
    inputs.public.asset_id = asset_id;
    inputs.private.zk_tree_root = compute_zk_leaf_hash(
        &inputs.private.unspendable_account,
        inputs.private.transfer_count,
        asset_id,
        inputs.private.input_amount,
    );
    inputs
}

// ============================================================================
// Client-side (private batch): one-shot aggregation, no queue
// ============================================================================

#[test]
fn aggregate_single_proof() {
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    // A single proof in a 2-slot batch exercises dummy padding.
    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof])
        .expect("aggregation must succeed");
    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_proofs_into_tree() {
    // All proofs must be from the SAME BLOCK for fixed-structure aggregation.
    let inputs = CircuitInputs::test_inputs_0();

    let proof_0 = make_leaf_proof(&inputs);
    let proof_1 = make_leaf_proof(&inputs);

    let pi0 = PublicCircuitInputs::try_from_proof(&proof_0).unwrap();
    let pi1 = PublicCircuitInputs::try_from_proof(&proof_1).unwrap();

    println!("proof_0 public inputs = {:?}", pi0);
    println!("proof_1 public inputs = {:?}", pi1);

    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof_0, proof_1])
        .expect("aggregation must succeed");
    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn commit_rejects_nonzero_asset_id_when_dummy_padding_is_needed() {
    // Tampering with asset_id invalidates the proof cryptographically, but the
    // prover's commit API does not verify proofs; the asset-id padding
    // preflight must still reject it before witness filling.
    let mut proof = make_leaf_proof(&CircuitInputs::test_inputs_0());
    proof.public_inputs[0] = F::from_canonical_u64(1);

    let prover = make_private_batch_prover();
    let err = prover.commit(vec![proof]).unwrap_err();
    assert!(err.to_string().contains("dummy proofs use asset_id=0"));
}

#[test]
fn aggregate_rejects_empty_batch() {
    // Without leaf proofs, commit would pad the entire batch with the dummy
    // template and prove an all-dummy private batch that settles nothing.
    // The client entry point must reject that instead (the intentional
    // all-dummy template is built on the circuit-build path, not here).
    let err = make_private_batch_prover().aggregate(vec![]).unwrap_err();
    assert!(err.to_string().contains("no leaf proofs"), "got: {err}");
}

#[test]
fn commit_rejects_batch_incompatible_proofs() {
    // Two individually valid proofs whose metadata the private-batch circuit's
    // cross-slot constraints reject (different asset ids) must fail fast at
    // commit time, not minutes later inside proving.
    let proof_asset_0 = make_leaf_proof(&CircuitInputs::test_inputs_0());
    let proof_asset_5 = make_leaf_proof(&test_inputs_with_asset(5));

    let prover = make_private_batch_prover();
    let err = prover
        .commit(vec![proof_asset_0, proof_asset_5])
        .unwrap_err();
    assert!(err.to_string().contains("asset"), "got: {err}");
}

#[test]
fn full_batch_of_same_nonzero_asset_aggregates() {
    // Sanity check for the fail-fast path: a FULL batch of same-asset proofs
    // needs no dummy padding, so a non-native asset is fine and the
    // compatibility preflight lets it through to real proving.
    let inputs = test_inputs_with_asset(5);
    let proof_0 = make_leaf_proof(&inputs);
    let proof_1 = make_leaf_proof(&inputs);

    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof_0, proof_1])
        .expect("full same-asset batch must aggregate");
    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

/// This simulates a CLI-ish flow without prebuilt binaries:
/// 1. Generate proofs from separate prover instances
/// 2. Serialize proof bytes (hex like the CLI handoff format)
/// 3. Deserialize using a fresh common_data
/// 4. Aggregate them one-shot
#[test]
fn aggregate_proofs_from_separate_prover_instances_hex_serialized() {
    setup_test_binaries();

    // Proof 1 from prover A
    let prover_a = WormholeProver::new(circuit_config());
    let inputs_1 = CircuitInputs::test_inputs_0();
    let proof_1 = prover_a.commit(&inputs_1).unwrap().prove().unwrap();
    let proof_1_hex = hex::encode(proof_1.to_bytes());

    // Proof 2 from prover B (same block)
    let prover_b = WormholeProver::new(circuit_config());
    let inputs_2 = CircuitInputs::test_inputs_0();
    let proof_2 = prover_b.commit(&inputs_2).unwrap().prove().unwrap();
    let proof_2_hex = hex::encode(proof_2.to_bytes());

    // Use fresh common_data to deserialize like CLI would
    let deser_common_data = WormholeProver::new(circuit_config()).circuit_data.common;

    let proof_1_bytes = hex::decode(&proof_1_hex).expect("Failed to decode proof 1 hex");
    let proof_2_bytes = hex::decode(&proof_2_hex).expect("Failed to decode proof 2 hex");

    let proof_1_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_1_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 1");

    let proof_2_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_2_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 2");

    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof_1_deserialized, proof_2_deserialized])
        .expect("Aggregation failed");

    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof verification failed");
}

#[test]
fn private_batch_commit_rejects_malformed_full_batch_at_api_boundary() {
    // A full 2-proof batch where one proof has the wrong public-input length must
    // be rejected at the API boundary instead of panicking in witness assignment.
    // Previously the length check ran only when dummy padding was needed (#97073).
    let mut malformed = make_leaf_proof(&CircuitInputs::test_inputs_0());
    malformed.public_inputs.pop();
    let valid = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let prover = make_private_batch_prover();
    let err = prover.commit(vec![malformed, valid]).unwrap_err();
    assert!(
        err.to_string()
            .contains("leaf proof public input length mismatch"),
        "got: {err}"
    );
}

#[test]
fn private_batch_prover_rejects_poisoned_dummy_template() {
    setup_test_binaries();
    // A tampered dummy_proof.bin must be rejected when the prover loads its
    // binaries. Otherwise the poisoned template would be padded into every
    // partial batch, replaying its payout once per empty slot via the circuit's
    // exit-dedup sum (leaf-level analogue of #97026).
    let poisoned_dir = test_bins_root().join("private-poisoned-dummy");
    let _ = std::fs::remove_dir_all(&poisoned_dir);
    std::fs::create_dir_all(&poisoned_dir).unwrap();
    for entry in std::fs::read_dir(private_bins_dir()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), poisoned_dir.join(entry.file_name())).unwrap();
    }

    // Sentinel-neutral tampering: block_hash and outputs stay zero, so only the
    // cryptographic check can catch it.
    let mut poisoned = make_leaf_proof(&CircuitInputs::test_inputs_0());
    poisoned.public_inputs[4] = F::from_canonical_u64(0xdead_beef); // nullifier felt
    std::fs::write(poisoned_dir.join("dummy_proof.bin"), poisoned.to_bytes()).unwrap();

    let err = PrivateBatchProver::new_from_binaries_dir(&poisoned_dir)
        .expect_err("poisoned dummy template must be rejected at load time");
    assert!(
        err.to_string()
            .contains("dummy leaf proof template failed verification"),
        "got: {err}"
    );

    // A template with a non-zero payout must be rejected by the sentinel check.
    let mut nonzero_payout = make_leaf_proof(&CircuitInputs::test_inputs_0());
    nonzero_payout.public_inputs[1] = F::from_canonical_u64(7); // output_amount_1
    std::fs::write(
        poisoned_dir.join("dummy_proof.bin"),
        nonzero_payout.to_bytes(),
    )
    .unwrap();

    let err = PrivateBatchProver::new_from_binaries_dir(&poisoned_dir)
        .expect_err("non-zero-payout dummy template must be rejected at load time");
    assert!(
        err.to_string().contains("non-zero output amounts"),
        "got: {err}"
    );

    // The pristine directory still loads fine (sanity check).
    PrivateBatchProver::new_from_binaries_dir(&private_bins_dir())
        .expect("pristine binaries must still load");

    let _ = std::fs::remove_dir_all(&poisoned_dir);
}

// ============================================================================
// Miner-side (public batch): pooled aggregation
// ============================================================================

/// Build (once) a real private-batch proof compatible with the public-batch
/// test artifacts. Cached because private aggregation costs minutes.
fn make_private_batch_proof_in_public_dir() -> ProofWithPublicInputs<F, C, D> {
    static PROOF: OnceLock<ProofWithPublicInputs<F, C, D>> = OnceLock::new();
    PROOF
        .get_or_init(|| {
            setup_public_test_binaries();
            let dir = public_bins_dir();
            // Non-dummy inputs: the aggregator refuses the dummy bucket.
            let leaf = make_leaf_proof_in(&dir, &test_inputs_with_real_block());
            PrivateBatchProver::new_from_binaries_dir(&dir)
                .expect("load private-batch prover from public test binaries")
                .aggregate(vec![leaf])
                .expect("private aggregate")
        })
        .clone()
}

#[test]
fn pool_rejects_invalid_proofs_and_aggregates_by_bucket() {
    setup_public_test_binaries();
    let dir = public_bins_dir();
    let address = BytesDigest::try_from([1u8; 32]).expect("valid address");

    let private_batch_proof = make_private_batch_proof_in_public_dir();
    let mut aggregator = PublicBatchAggregator::new(&dir, address).expect("public aggregator");

    // Shape rejection: a leaf proof is not a private-batch proof.
    let leaf = make_leaf_proof_in(&dir, &CircuitInputs::test_inputs_0());
    let err = aggregator.push_proof(leaf).unwrap_err();
    assert!(
        err.to_string().contains("public input length mismatch"),
        "got: {err}"
    );

    // Cryptographic rejection: valid shape, tampered contents. A proof admitted
    // into the pool despite being invalid would wedge its bucket forever, since
    // buckets only drain on successful aggregation (#97067).
    let mut tampered = private_batch_proof.clone();
    tampered.public_inputs[1] = F::from_canonical_u64(9); // asset_id felt
    let err = aggregator.push_proof(tampered).unwrap_err();
    assert!(
        err.to_string().contains("verification failed"),
        "got: {err}"
    );
    assert_eq!(aggregator.pool_len(), 0, "rejected proofs must not pool");

    // A valid proof is admitted, keyed by its (block, asset, fee) metadata.
    let key = aggregator
        .push_proof(private_batch_proof)
        .expect("valid private-batch proof must be admitted");
    assert_eq!(aggregator.pool_len(), 1);
    let stats = aggregator.bucket_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].key, key);
    assert!(stats[0].is_full(), "batch_size=1 bucket must be full");

    // Aggregating the bucket produces a verifiable public batch and drains it.
    let aggregated = aggregator.aggregate(&key).expect("public aggregate");
    aggregator
        .verify(aggregated)
        .expect("public-batch proof must verify");
    assert_eq!(aggregator.pool_len(), 0, "bucket must drain on success");

    // Aggregating a missing bucket is an error, and the pool stays usable.
    let err = aggregator.aggregate(&key).unwrap_err();
    assert!(err.to_string().contains("no pooled proofs"), "got: {err}");

    // The dummy sentinel bucket (block_hash == 0) is refused outright: an
    // all-dummy public batch settles nothing, so proving it wastes minutes.
    let dummy_key = BatchKey {
        block_hash: BytesDigest::default(),
        ..key
    };
    let err = aggregator.aggregate(&dummy_key).unwrap_err();
    assert!(err.to_string().contains("dummy"), "got: {err}");
}

#[test]
fn public_batch_verify_rejects_proof_bound_to_a_different_aggregator_address() {
    setup_public_test_binaries();
    let dir = public_bins_dir();

    let private_batch_proof = make_private_batch_proof_in_public_dir();

    let address_a = BytesDigest::try_from([1u8; 32]).expect("valid address a");
    let address_b = BytesDigest::try_from([2u8; 32]).expect("valid address b");
    assert_ne!(address_a, address_b, "sanity: addresses must differ");

    // Produce a public-batch proof bound to address_a (this also exercises the
    // dummy-template verification + count/shape validation in new_from_bytes).
    let public_batch_proof = {
        let mut agg = PublicBatchAggregator::new(&dir, address_a).expect("public aggregator a");
        let key = agg.push_proof(private_batch_proof.clone()).unwrap();
        agg.aggregate(&key).expect("public aggregate")
    };

    // The producing backend accepts its own proof.
    PublicBatchAggregator::new(&dir, address_a)
        .expect("public aggregator a")
        .verify(public_batch_proof.clone())
        .expect("same-address proof must verify");

    // A backend configured for a different aggregator address must reject it (#96981).
    let err = PublicBatchAggregator::new(&dir, address_b)
        .expect("public aggregator b")
        .verify(public_batch_proof)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match configured aggregator address"),
        "got: {err}"
    );
}
