#![cfg(test)]

use wormhole_aggregator::aggregator::WormholeProofAggregator;
use wormhole_circuit::inputs::{AggregatedPublicCircuitInputs, CircuitInputs, PublicCircuitInputs};
use wormhole_prover::WormholeProver;

use crate::aggregator::circuit_config;
use test_helpers::{TestAggrInputs, TestInputs};

#[test]
fn push_proof_to_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());
    aggregator.push_proof(proof).unwrap();

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), 1);
}

#[test]
fn push_proof_to_full_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());

    // Fill up the proof buffer.
    for _ in 0..aggregator.config.num_leaf_proofs {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let result = aggregator.push_proof(proof.clone());
    assert!(result.is_err());

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), aggregator.config.num_leaf_proofs);
}

#[ignore]
#[test]
fn aggregate_single_proof() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());
    aggregator.push_proof(proof).unwrap();

    aggregator.aggregate().unwrap();
}

/// We are ignoring ths test for now. We need to update the aggregator to handle the new asset id leaf input.
#[ignore]
#[test]
fn aggregate_proofs_into_tree() {
    // Create a proof.
    let inputs_vec = CircuitInputs::test_aggr_inputs();
    let mut proofs = Vec::new();
    for (idx, inputs) in inputs_vec.iter().enumerate() {
        let prover = WormholeProver::new(circuit_config());
        let proof = prover.commit(inputs).unwrap().prove().unwrap();
        let public_inputs = PublicCircuitInputs::try_from(&proof).unwrap();
        println!(
            "public inputs of original proof number {:?} = {:?}",
            idx, public_inputs
        );
        proofs.push(proof);
    }

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());

    // Fill up the proof buffer.
    for i in 0..aggregator.config.num_leaf_proofs {
        aggregator.push_proof(proofs[i % 2].clone()).unwrap();
    }

    let aggregated_public_inputs_ref = aggregator
        .parse_aggregated_public_inputs_from_proof_buffer()
        .unwrap();

    let aggregated_proof = aggregator.aggregate().unwrap(); // AggregatedProof<F, C, D>

    let aggregated_public_inputs = AggregatedPublicCircuitInputs::try_from_slice(
        aggregated_proof.proof.public_inputs.as_slice(),
    )
    .unwrap();

    // Check that the aggregated_public_inputs_ref equals the aggregated_public_inputs

    assert_eq!(aggregated_public_inputs, aggregated_public_inputs_ref);

    // pretty print aggregated_public_inputs
    print!("{:?}", aggregated_public_inputs);

    aggregated_proof
        .circuit_data
        .verify(aggregated_proof.proof)
        .unwrap();
}

/// We are ignoring ths test for now. We need to update the aggregator to handle the new asset id leaf input.
#[ignore]
#[test]
fn aggregate_half_full_proof_array_into_tree() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator = WormholeProofAggregator::from_circuit_config(circuit_config());

    // Fill up the proof buffer.
    for _ in 0..aggregator.config.num_leaf_proofs {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let aggregated_proof = aggregator.aggregate().unwrap();
    aggregated_proof
        .circuit_data
        .verify(aggregated_proof.proof)
        .unwrap();
}
