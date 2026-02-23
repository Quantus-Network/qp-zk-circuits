#![cfg(test)]

use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::PublicCircuitInputs;
use test_helpers::TestInputs;
use wormhole_aggregator::aggregator::WormholeAggregator;
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::aggregation::AggregationConfig;
use zk_circuits_common::circuit::{C, D, F};

use crate::aggregator::circuit_config;

/// Fast local unit-test aggregation config (2 leaf proofs).
fn test_aggregation_config() -> AggregationConfig {
    AggregationConfig::new(2)
}

fn make_leaf_proof(inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    let prover = WormholeProver::new(circuit_config());
    prover.commit(inputs).unwrap().prove().unwrap()
}

#[test]
fn push_proof_to_buffer() {
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), test_aggregation_config())
            .unwrap();

    aggregator.push_proof(proof).unwrap();

    let proofs_buffer = aggregator.leaf_proofs_buffer;
    assert_eq!(proofs_buffer.len(), 1);
}

#[test]
fn push_proof_to_full_buffer() {
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let aggregation_config = test_aggregation_config();
    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), aggregation_config).unwrap();

    // Fill the buffer
    for _ in 0..aggregator.config.num_leaf_proofs {
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
fn aggregate_single_proof() {
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), test_aggregation_config())
            .unwrap();

    aggregator.push_proof(proof).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify_aggregated_proof(aggregated)
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

    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), test_aggregation_config())
            .unwrap();

    aggregator.push_proof(proof_0).unwrap();
    aggregator.push_proof(proof_1).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify_aggregated_proof(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_half_full_proof_array_into_tree() {
    // Intentionally only push one proof into a 2-proof aggregator to exercise padding.
    let proof = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), test_aggregation_config())
            .unwrap();

    aggregator.push_proof(proof).unwrap();

    let aggregated = aggregator.aggregate().unwrap();
    aggregator
        .verify_aggregated_proof(aggregated)
        .expect("Aggregated proof should verify");
}

/// This simulates a CLI-ish flow without prebuilt binaries:
/// 1. Generate proofs from separate prover instances
/// 2. Serialize proof bytes
/// 3. Deserialize using a fresh common_data
/// 4. Aggregate them
#[test]
fn aggregate_proofs_from_separate_prover_instances_serialized() {
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
    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), test_aggregation_config())
            .unwrap();

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
        .verify_aggregated_proof(aggregated)
        .expect("Aggregated proof verification failed");

    println!("=== Test passed ===");
}

/// Same as above but includes hex encoding/decoding to match CLI proof handoff format.
#[test]
fn aggregate_proofs_from_separate_prover_instances_hex_serialized() {
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

    let mut aggregator =
        WormholeAggregator::from_circuit_config(circuit_config(), test_aggregation_config())
            .unwrap();

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
        .verify_aggregated_proof(aggregated)
        .expect("Aggregated proof verification failed");

    println!("=== Test passed ===");
}
