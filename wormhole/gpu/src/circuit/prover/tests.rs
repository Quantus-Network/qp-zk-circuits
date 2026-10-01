use super::*;
use plonky2::fri::FriReductionStrategy;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;

#[test]
fn workspace_ranges_and_pow_retries_are_checked() {
    let layout = ProvingWorkspaceLayout::new([&[1, 2], &[3], &[4, 5], &[6], &[], &[7, 8]]);
    assert_eq!(layout.first, [0, 2, 3, 5, 6, 6]);
    assert_eq!(layout.fields, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(next_pow_base(0, 17).unwrap(), 17);
    assert_eq!(next_pow_base(F::ORDER - 2, 1).unwrap(), F::ORDER - 1);
    assert!(next_pow_base(F::ORDER - 1, 1).is_err());
    assert!(next_pow_base(u64::MAX, 1).is_err());
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn coordinator_handles_zero_fri_rounds_and_reuses_workspace_after_input_errors() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![]);
    config.fri_config.proof_of_work_bits = 8;
    config.security_bits = 80;
    let mut builder = CircuitBuilder::<F, 2>::new(config);
    let input = builder.add_virtual_target();
    let square = builder.mul(input, input);
    builder.register_public_input(square);
    let circuit = builder.build::<C>();
    assert!(circuit.common.fri_params.reduction_arity_bits.is_empty());
    let prepared = PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())?;
    let mut workspace = prepared.prepare_workspace(&context)?;
    assert_eq!(
        workspace.allocated_bytes(),
        prepared
            .proof_workspace_field_counts()
            .iter()
            .map(|&n| n as u64 * 8)
            .sum()
    );
    let incomplete = PartitionWitness::new(
        circuit.common.config.num_wires,
        circuit.common.degree(),
        &circuit.prover_only.representative_map,
    );
    assert_eq!(
        prepared
            .prove_with_partition_witness(&context, &mut workspace, incomplete.clone())
            .unwrap_err()
            .to_string(),
        "missing public-input witness value"
    );
    let mut wrong_shape = incomplete.clone();
    wrong_shape.degree *= 2;
    assert_eq!(
        prepared
            .prove_with_partition_witness(&context, &mut workspace, wrong_shape)
            .unwrap_err()
            .to_string(),
        "partition witness does not match prepared circuit"
    );
    let mut wrong_map = circuit.prover_only.representative_map.clone();
    wrong_map[0] = (wrong_map[0] + 1) % wrong_map.len();
    let mut wrong_witness = incomplete;
    wrong_witness.representative_map = &wrong_map;
    assert_eq!(
        prepared
            .prove_with_partition_witness(&context, &mut workspace, wrong_witness)
            .unwrap_err()
            .to_string(),
        "partition witness does not match prepared circuit"
    );
    // Two distinct inputs overwrite the same allocations and generate fresh
    // transcripts/proofs; neither the result nor the public inputs are cached.
    for value in [F::NEG_ONE, F::from_canonical_usize(2)] {
        let mut inputs = PartialWitness::new();
        inputs.set_target(input, value)?;
        let proof = prepared.prove(&context, &mut workspace, inputs)?;
        assert_eq!(proof.public_inputs, [value * value]);
        assert!(proof
            .proof
            .opening_proof
            .commit_phase_merkle_caps
            .is_empty());
        assert!(proof
            .proof
            .opening_proof
            .query_round_proofs
            .iter()
            .all(|round| round.steps.is_empty()));
        circuit.verify(proof)?;
    }
    Ok(())
}
