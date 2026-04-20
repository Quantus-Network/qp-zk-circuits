#![cfg(test)]

use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::Field;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::PublicCircuitInputs;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Once,
    time::{SystemTime, UNIX_EPOCH},
};
use test_helpers::TestInputs;
use wormhole_aggregator::{
    aggregator::{AggregationBackend, Layer0Aggregator},
    dummy_proof::load_dummy_proof,
    layer0::circuit::constants::INNER_NUM_LEAVES,
};
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};

use crate::aggregator::circuit_config;

const TEST_OUTPUT_DIR: &str = "tmp-test-bins";

static TEST_INIT: Once = Once::new();

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

fn load_leaf_dummy_proof() -> ProofWithPublicInputs<F, C, D> {
    setup_test_binaries();

    let prover_path = format!("{}/prover.bin", TEST_OUTPUT_DIR);
    let common_path = format!("{}/common.bin", TEST_OUTPUT_DIR);
    let dummy_proof_path = format!("{}/dummy_proof.bin", TEST_OUTPUT_DIR);

    let prover = WormholeProver::new_from_files(Path::new(&prover_path), Path::new(&common_path))
        .expect("Failed to create prover from binaries");
    let dummy_proof_bytes =
        fs::read(Path::new(&dummy_proof_path)).expect("Failed to read serialized dummy proof");

    load_dummy_proof(dummy_proof_bytes, &prover.circuit_data.common)
        .expect("Failed to deserialize dummy proof")
}

fn make_aggregator() -> Layer0Aggregator {
    setup_test_binaries();
    Layer0Aggregator::new(TEST_OUTPUT_DIR).unwrap()
}

fn temp_bins_copy(name: &str) -> PathBuf {
    setup_test_binaries();

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("qp-layer0-{name}-{suffix}"));
    fs::create_dir_all(&dir).unwrap();

    for entry in fs::read_dir(TEST_OUTPUT_DIR).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        if file_type.is_file() {
            fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
        }
    }

    dir
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
    // Intentionally only push one proof into the shipping 2x8 aggregator to exercise padding.
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator = make_aggregator();

    aggregator.push_proof(proof).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_rejects_nonzero_asset_id_when_dummy_padding_is_needed() {
    setup_test_binaries();
    let mut proof = make_leaf_proof(&CircuitInputs::test_inputs_0());
    proof.public_inputs[0] = F::from_canonical_u64(1);

    let mut aggregator = make_aggregator();
    aggregator.push_proof(proof).unwrap();

    let err = aggregator.aggregate().unwrap_err();
    assert!(err
        .to_string()
        .contains("dummy padding requires all real proofs to use asset_id=0"));
}

#[test]
fn aggregate_allows_real_proof_after_dummy_prefill_across_inner_split() {
    setup_test_binaries();
    let mut aggregator = make_aggregator();
    let dummy_proof = load_leaf_dummy_proof();

    for _ in 0..INNER_NUM_LEAVES {
        aggregator.push_proof(dummy_proof.clone()).unwrap();
    }
    aggregator
        .push_proof(make_leaf_proof(&CircuitInputs::test_inputs_0()))
        .unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_uses_cached_layer0_artifacts() {
    let bins_dir = temp_bins_copy("cached-warm-path");
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator = Layer0Aggregator::new(&bins_dir).unwrap();

    fs::remove_file(bins_dir.join("inner_prover.bin")).unwrap();
    fs::remove_file(bins_dir.join("inner_common.bin")).unwrap();
    fs::remove_file(bins_dir.join("inner_verifier.bin")).unwrap();
    fs::remove_file(bins_dir.join("inner_targets.bin")).unwrap();
    fs::remove_file(bins_dir.join("outer_prover.bin")).unwrap();
    fs::remove_file(bins_dir.join("outer_common.bin")).unwrap();
    fs::remove_file(bins_dir.join("outer_verifier.bin")).unwrap();
    fs::remove_file(bins_dir.join("outer_targets.bin")).unwrap();
    fs::remove_file(bins_dir.join("aggregated_prover.bin")).unwrap();
    fs::remove_file(bins_dir.join("aggregated_targets.bin")).unwrap();
    fs::remove_file(bins_dir.join("common.bin")).unwrap();
    fs::remove_file(bins_dir.join("verifier.bin")).unwrap();
    fs::remove_file(bins_dir.join("dummy_proof.bin")).unwrap();
    fs::remove_file(bins_dir.join("config.json")).unwrap();

    aggregator.push_proof(proof).unwrap();
    let aggregated = aggregator.aggregate().unwrap();
    aggregator.verify(aggregated).unwrap();

    fs::remove_dir_all(bins_dir).unwrap();
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
