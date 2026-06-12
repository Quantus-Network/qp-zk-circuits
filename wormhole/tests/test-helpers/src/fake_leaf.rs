//! Fake leaf circuit for testing aggregation in isolation.
//!
//! This module provides helpers to build and prove a minimal "fake" leaf circuit
//! whose public inputs match the Wormhole leaf PI layout. This allows testing
//! aggregation circuits without needing real wormhole proofs.

use plonky2::{
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, circuit_data::CircuitData,
        proof::ProofWithPublicInputs,
    },
};
use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN;
use zk_circuits_common::circuit::{C, D, F};

/// Build a fake leaf circuit whose public inputs match the Wormhole leaf PI layout.
///
/// Returns the circuit data and the public input targets.
pub fn build_fake_leaf_circuit() -> (CircuitData<F, C, D>, [Target; LEAF_PI_LEN]) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let pis_vec = builder.add_virtual_targets(LEAF_PI_LEN);
    let pis: [Target; LEAF_PI_LEN] = pis_vec
        .clone()
        .try_into()
        .expect("exactly LEAF_PI_LEN targets");

    // Minimal constraints to mimic real leaf circuit
    builder.range_check(pis[1], 32); // output_amount_1
    builder.range_check(pis[2], 32); // output_amount_2
    builder.range_check(pis[3], 32); // volume_fee_bps

    builder.register_public_inputs(&pis_vec);

    let data = builder.build::<C>();
    (data, pis)
}

/// Build a fake leaf circuit without returning targets (for profiling).
pub fn build_fake_leaf_circuit_data_only() -> CircuitData<F, C, D> {
    build_fake_leaf_circuit().0
}

/// Prove a fake leaf with the given public inputs.
pub fn prove_fake_leaf(
    leaf_data: &CircuitData<F, C, D>,
    leaf_targets: &[Target; LEAF_PI_LEN],
    pis: [F; LEAF_PI_LEN],
) -> ProofWithPublicInputs<F, C, D> {
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    for (t, v) in leaf_targets.iter().zip(pis.iter()) {
        pw.set_target(*t, *v).unwrap();
    }
    leaf_data.prove(pw).unwrap()
}

/// Generate a fake leaf proof with the given public inputs (builds circuit internally).
pub fn prove_fake_leaf_standalone(
    pis: [F; LEAF_PI_LEN],
) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    let (circuit_data, targets) = build_fake_leaf_circuit();
    let mut pw = plonky2::iop::witness::PartialWitness::new();

    for (t, v) in targets.into_iter().zip(pis.into_iter()) {
        pw.set_target(t, v).unwrap();
    }

    let proof = circuit_data.prove(pw).unwrap();
    (proof, circuit_data)
}
