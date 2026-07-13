#![cfg(test)]

use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::Field;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{BytesDigest, PublicCircuitInputs};
use std::path::Path;
use std::sync::Once;
use test_helpers::{compute_zk_leaf_hash, TestInputs};
use wormhole_aggregator::aggregator::{
    AggregationBackend, PrivateBatchAggregator, PublicBatchAggregator,
};
use wormhole_aggregator::private_batch::prover::PrivateBatchProver;
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};

use crate::aggregator::circuit_config;

const TEST_OUTPUT_DIR: &str = "tmp-test-bins";
const PUBLIC_TEST_OUTPUT_DIR: &str = "tmp-test-public-bins";

static TEST_INIT: Once = Once::new();
static PUBLIC_TEST_INIT: Once = Once::new();

extern "C" fn cleanup_test_output_dir() {
    // Best-effort cleanup (don’t panic during shutdown)
    let _ = std::fs::remove_dir_all(TEST_OUTPUT_DIR);
}

fn setup_test_binaries() {
    TEST_INIT.call_once(|| {
        generate_all_circuit_binaries(TEST_OUTPUT_DIR, true, 2, None)
            .expect("Failed to generate test circuit binaries");

        // Register a process-exit cleanup so the directory is removed once all tests finish.
        unsafe {
            // Ignore return value; if registration fails we simply won't auto-clean.
            let _ = libc::atexit(cleanup_test_output_dir);
        }
    });
}

fn make_leaf_proof(inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    setup_test_binaries();

    let prover_path = format!("{}/prover.bin", TEST_OUTPUT_DIR);
    let common_path = format!("{}/common.bin", TEST_OUTPUT_DIR);
    let prover = WormholeProver::new_from_files(Path::new(&prover_path), Path::new(&common_path))
        .expect("Failed to create prover from binaries");
    prover.commit(inputs).unwrap().prove().unwrap()
}
fn make_aggregator() -> PrivateBatchAggregator {
    setup_test_binaries();
    PrivateBatchAggregator::new(TEST_OUTPUT_DIR).unwrap()
}

fn make_private_batch_prover() -> PrivateBatchProver {
    setup_test_binaries();
    PrivateBatchProver::new_from_binaries_dir(Path::new(TEST_OUTPUT_DIR))
        .expect("Failed to load private-batch prover from generated binaries")
}

fn setup_public_test_binaries() {
    PUBLIC_TEST_INIT.call_once(|| {
        // Smallest public-batch circuit (1 inner private-batch of 1 leaf) to keep
        // artifact generation fast.
        generate_all_circuit_binaries(PUBLIC_TEST_OUTPUT_DIR, true, 1, Some(1))
            .expect("Failed to generate public-batch test circuit binaries");
    });
}

#[test]
fn push_proof_to_buffer() {
    setup_test_binaries();
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator = make_aggregator();

    aggregator.push_proof(proof).unwrap();

    assert_eq!(aggregator.buffer_len(), 1);
}

#[test]
fn push_proof_to_full_buffer() {
    setup_test_binaries();
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator = make_aggregator();

    // Fill the buffer
    for _ in 0..aggregator.batch_size() {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    // One more push should fail
    let result = aggregator.push_proof(proof);
    assert!(
        result.is_err(),
        "expected error when pushing to full buffer"
    );
}

#[test]
fn push_proof_rejects_malformed_public_input_length() {
    setup_test_binaries();
    let mut proof = make_leaf_proof(&CircuitInputs::test_inputs_0());
    proof.public_inputs.pop();

    let mut aggregator = make_aggregator();
    let err = aggregator.push_proof(proof).unwrap_err();
    assert!(err
        .to_string()
        .contains("leaf proof public input length mismatch"));
}

#[test]
fn aggregate_single_proof() {
    setup_test_binaries();
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator = make_aggregator();

    aggregator.push_proof(proof).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_proofs_into_tree() {
    setup_test_binaries();
    // All proofs must be from the SAME BLOCK for fixed-structure aggregation.
    let inputs = CircuitInputs::test_inputs_0();

    let proof_0 = make_leaf_proof(&inputs);
    let proof_1 = make_leaf_proof(&inputs);

    let pi0 = PublicCircuitInputs::try_from_proof(&proof_0).unwrap();
    let pi1 = PublicCircuitInputs::try_from_proof(&proof_1).unwrap();

    println!("proof_0 public inputs = {:?}", pi0);
    println!("proof_1 public inputs = {:?}", pi1);

    let mut aggregator = make_aggregator();

    aggregator.push_proof(proof_0).unwrap();
    aggregator.push_proof(proof_1).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_half_full_proof_array_into_tree() {
    setup_test_binaries();
    // Intentionally only push one proof into a 2-proof aggregator to exercise padding.
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator = make_aggregator();

    aggregator.push_proof(proof).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn commit_rejects_nonzero_asset_id_when_dummy_padding_is_needed() {
    setup_test_binaries();
    // Tampering with asset_id invalidates the proof cryptographically, so the
    // aggregator now rejects it at push time (see below). The asset-id padding
    // preflight is still reachable through the prover's commit API, which does
    // not verify proofs itself.
    let mut proof = make_leaf_proof(&CircuitInputs::test_inputs_0());
    proof.public_inputs[0] = F::from_canonical_u64(1);

    let prover = make_private_batch_prover();
    let err = prover.commit(vec![proof]).unwrap_err();
    assert!(err.to_string().contains("dummy proofs use asset_id=0"));
}

#[test]
fn push_proof_rejects_invalid_proof_and_queue_stays_usable() {
    setup_test_binaries();
    // An invalid proof (correct PI length, tampered contents) must be rejected at
    // push time. Since aggregate() only drains the queue on success (#97067), a
    // poisoned proof accepted into the queue would make every retry fail on the
    // same batch, wedging the aggregator permanently.
    let mut tampered = make_leaf_proof(&CircuitInputs::test_inputs_0());
    tampered.public_inputs[0] = F::from_canonical_u64(1);

    let mut aggregator = make_aggregator();
    let err = aggregator.push_proof(tampered).unwrap_err();
    assert!(
        err.to_string()
            .contains("refusing to queue invalid leaf proof"),
        "got: {err}"
    );
    assert_eq!(
        aggregator.buffer_len(),
        0,
        "rejected proof must not be queued"
    );

    // The aggregator remains fully usable: a valid proof pushes and aggregates.
    let valid = make_leaf_proof(&CircuitInputs::test_inputs_0());
    aggregator.push_proof(valid).unwrap();
    let aggregated = aggregator.aggregate().expect("aggregation must succeed");
    aggregator
        .verify(aggregated)
        .expect("aggregated proof should verify");
}

#[test]
fn push_proof_rejects_batch_incompatible_proof_and_buffer_is_recoverable() {
    setup_test_binaries();
    // Two individually valid proofs whose metadata the private-batch circuit's
    // cross-slot constraints reject (different asset_ids) must not both be
    // admitted: aggregate() would fail deterministically and, since the queue
    // only drains on success (#97067), every retry would fail on the same
    // batch, wedging the aggregator permanently.
    let proof_asset_0 = make_leaf_proof(&CircuitInputs::test_inputs_0());

    // A cryptographically valid proof for asset_id=5: same fixture, but the
    // asset is part of the ZK leaf hash, so the tree root must be recomputed.
    let proof_asset_5 = {
        let mut inputs = CircuitInputs::test_inputs_0();
        inputs.public.asset_id = 5;
        inputs.private.zk_tree_root = compute_zk_leaf_hash(
            &inputs.private.unspendable_account,
            inputs.private.transfer_count,
            5,
            inputs.private.input_amount,
        );
        make_leaf_proof(&inputs)
    };

    let mut aggregator = make_aggregator();
    aggregator.push_proof(proof_asset_0).unwrap();

    // Sanity: the incompatible proof is valid on its own; only the combination
    // with the queued asset-0 proof is rejected.
    let err = aggregator.push_proof(proof_asset_5.clone()).unwrap_err();
    assert!(
        err.to_string().contains("batch-incompatible") && err.to_string().contains("asset_id"),
        "got: {err}"
    );
    assert_eq!(
        aggregator.buffer_len(),
        1,
        "rejected proof must not be queued; queued proof must be retained"
    );

    // Recovery path: drain the queue and requeue as the operator sees fit.
    // The incompatible proof is admitted once the conflicting one is gone.
    let drained = aggregator.drain_buffer();
    assert_eq!(drained.len(), 1);
    assert_eq!(aggregator.buffer_len(), 0);
    aggregator.push_proof(proof_asset_5).unwrap();

    // The backend stays fully usable: requeue the drained proof set and
    // aggregate it successfully.
    let recovered = aggregator.drain_buffer();
    assert_eq!(recovered.len(), 1);
    for proof in drained {
        aggregator.push_proof(proof).unwrap();
    }
    let aggregated = aggregator.aggregate().expect("aggregation must succeed");
    aggregator
        .verify(aggregated)
        .expect("aggregated proof should verify");
}

/// This simulates a CLI-ish flow without prebuilt binaries:
/// 1. Generate proofs from separate prover instances
/// 2. Serialize proof bytes
/// 3. Deserialize using a fresh common_data
/// 4. Aggregate them
#[test]
fn aggregate_proofs_from_separate_prover_instances_serialized() {
    setup_test_binaries();
    println!("=== Testing local CLI-like flow with separate prover instances ===");

    // Proof 1 from prover A
    let prover_a = WormholeProver::new(circuit_config());
    let inputs_1 = CircuitInputs::test_inputs_0();
    let proof_1 = prover_a.commit(&inputs_1).unwrap().prove().unwrap();
    let proof_1_bytes = proof_1.to_bytes();

    // Proof 2 from prover B (same block)
    let prover_b = WormholeProver::new(circuit_config());
    let inputs_2 = CircuitInputs::test_inputs_0();
    let proof_2 = prover_b.commit(&inputs_2).unwrap().prove().unwrap();
    let proof_2_bytes = proof_2.to_bytes();

    // Create aggregator (local/in-memory path)
    let mut aggregator = make_aggregator();

    // Use fresh common_data to deserialize like CLI would
    let deser_common_data = WormholeProver::new(circuit_config()).circuit_data.common;

    let proof_1_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_1_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 1");

    let proof_2_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_2_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 2");

    aggregator.push_proof(proof_1_deserialized).unwrap();
    aggregator.push_proof(proof_2_deserialized).unwrap();

    let aggregated = aggregator.aggregate().expect("Aggregation failed");

    aggregator
        .verify(aggregated)
        .expect("Aggregated proof verification failed");

    println!("=== Test passed ===");
}

/// Same as above but includes hex encoding/decoding to match CLI proof handoff format.
#[test]
fn aggregate_proofs_from_separate_prover_instances_hex_serialized() {
    setup_test_binaries();
    println!("=== Testing local CLI-like flow with hex encoding ===");

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

    let mut aggregator = make_aggregator();

    let deser_common_data = WormholeProver::new(circuit_config()).circuit_data.common;

    let proof_1_bytes = hex::decode(&proof_1_hex).expect("Failed to decode proof 1 hex");
    let proof_2_bytes = hex::decode(&proof_2_hex).expect("Failed to decode proof 2 hex");

    let proof_1_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_1_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 1");

    let proof_2_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_2_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 2");

    aggregator.push_proof(proof_1_deserialized).unwrap();
    aggregator.push_proof(proof_2_deserialized).unwrap();

    let aggregated = aggregator.aggregate().expect("Aggregation failed");

    aggregator
        .verify(aggregated)
        .expect("Aggregated proof verification failed");

    println!("=== Test passed ===");
}

#[test]
fn private_batch_commit_rejects_malformed_full_batch_at_api_boundary() {
    setup_test_binaries();
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
    let poisoned_dir = Path::new("tmp-test-bins-poisoned-dummy");
    let _ = std::fs::remove_dir_all(poisoned_dir);
    std::fs::create_dir_all(poisoned_dir).unwrap();
    for entry in std::fs::read_dir(TEST_OUTPUT_DIR).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), poisoned_dir.join(entry.file_name())).unwrap();
    }

    // Sentinel-neutral tampering: block_hash and outputs stay zero, so only the
    // cryptographic check can catch it.
    let mut poisoned = make_leaf_proof(&CircuitInputs::test_inputs_0());
    poisoned.public_inputs[4] = F::from_canonical_u64(0xdead_beef); // nullifier felt
    std::fs::write(poisoned_dir.join("dummy_proof.bin"), poisoned.to_bytes()).unwrap();

    let err = PrivateBatchProver::new_from_binaries_dir(poisoned_dir)
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

    let err = PrivateBatchProver::new_from_binaries_dir(poisoned_dir)
        .expect_err("non-zero-payout dummy template must be rejected at load time");
    assert!(
        err.to_string().contains("non-zero output amounts"),
        "got: {err}"
    );

    // The pristine directory still loads fine (sanity check).
    PrivateBatchProver::new_from_binaries_dir(Path::new(TEST_OUTPUT_DIR))
        .expect("pristine binaries must still load");

    let _ = std::fs::remove_dir_all(poisoned_dir);
}

#[test]
fn public_batch_verify_rejects_proof_bound_to_a_different_aggregator_address() {
    setup_public_test_binaries();
    let dir = Path::new(PUBLIC_TEST_OUTPUT_DIR);

    // Build a real private-batch proof to feed the public-batch aggregator.
    let leaf = {
        let prover =
            WormholeProver::new_from_files(&dir.join("prover.bin"), &dir.join("common.bin"))
                .expect("load leaf prover");
        prover
            .commit(&CircuitInputs::test_inputs_0())
            .unwrap()
            .prove()
            .unwrap()
    };
    let private_batch_proof = {
        let mut agg = PrivateBatchAggregator::new(dir).expect("private aggregator");
        agg.push_proof(leaf).unwrap();
        agg.aggregate().expect("private aggregate")
    };

    let address_a = BytesDigest::try_from([1u8; 32]).expect("valid address a");
    let address_b = BytesDigest::try_from([2u8; 32]).expect("valid address b");
    assert_ne!(address_a, address_b, "sanity: addresses must differ");

    // Produce a public-batch proof bound to address_a (this also exercises the
    // dummy-template verification + count/shape validation in new_from_bytes).
    let public_batch_proof = {
        let mut agg = PublicBatchAggregator::new(dir, address_a).expect("public aggregator a");
        agg.push_proof(private_batch_proof.clone()).unwrap();
        agg.aggregate().expect("public aggregate")
    };

    // The producing backend accepts its own proof.
    PublicBatchAggregator::new(dir, address_a)
        .expect("public aggregator a")
        .verify(public_batch_proof.clone())
        .expect("same-address proof must verify");

    // A backend configured for a different aggregator address must reject it (#96981).
    let err = PublicBatchAggregator::new(dir, address_b)
        .expect("public aggregator b")
        .verify(public_batch_proof)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match configured aggregator address"),
        "got: {err}"
    );

    let _ = std::fs::remove_dir_all(dir);
}
