use super::*;
use crate::{ArithmeticKernels, ArithmeticPlan, FieldOperation};
use plonky2::field::polynomial::PolynomialValues;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::util::timing::TimingTree;

fn tiny_circuit() -> (CircuitData<F, C, 2>, plonky2::iop::target::Target) {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let input = builder.add_virtual_target();
    let duplicate = builder.add_virtual_target();
    builder.connect(input, duplicate);
    let square = builder.mul(input, duplicate);
    builder.register_public_input(square);
    (builder.build::<C>(), input)
}

#[test]
fn quotient_domain_uses_strided_lde_points() -> Result<()> {
    for (degree, rate, factor, expected) in [
        (16, 3, 8, (128, 128, 1)),
        (16, 4, 6, (256, 128, 2)),
        (16, 3, 1, (128, 16, 8)),
    ] {
        let (lde_rows, quotient_rows, step) = evaluation_domains(degree, rate, factor)?;
        assert_eq!((lde_rows, quotient_rows, step), expected);
        let lde_root = F::primitive_root_of_unity(lde_rows.ilog2() as usize);
        let quotient_root = F::primitive_root_of_unity(quotient_rows.ilog2() as usize);
        assert_eq!(lde_root.exp_u64(step as u64), quotient_root);
    }
    assert!(evaluation_domains(16, 1, 6).is_err());
    assert!(evaluation_domains(16, 3, 0).is_err());
    assert!(evaluation_domains(16, usize::BITS as usize, 1).is_err());
    Ok(())
}

#[test]
fn preparation_rejects_unsupported_and_mismatched_circuit_data_without_gpu() {
    let (mut circuit, _) = tiny_circuit();
    let options = PreparationOptions::default();
    let limit = 1 << 30;
    let rejected = |circuit: &CircuitData<F, C, 2>, options, limit, message| {
        let error = CircuitLayout::new(circuit, options, limit)
            .err()
            .expect("preparation must reject invalid input");
        assert_eq!(error.to_string(), message);
    };
    #[cfg(feature = "constraint-export")]
    {
        circuit.common.fri_params.config.cap_height += 1;
        rejected(
            &circuit,
            options,
            limit,
            "FRI parameters do not match circuit configuration",
        );
        circuit.common.fri_params.config.cap_height -= 1;
        circuit.common.fri_params.leaf_hiding = true;
        rejected(
            &circuit,
            options,
            limit,
            "FRI parameters do not match circuit configuration",
        );
        circuit.common.fri_params.leaf_hiding = false;
    }
    assert!(CircuitLayout::new(&circuit, options, limit).is_ok());
    for invalid in [
        PreparationOptions {
            max_columns_per_batch: 0,
            ..options
        },
        PreparationOptions {
            commitment_chunk_rows: 0,
            ..options
        },
        PreparationOptions {
            quotient_chunk_rows: 0,
            ..options
        },
    ] {
        rejected(
            &circuit,
            invalid,
            limit,
            "preparation resource limits must be nonzero",
        );
    }
    circuit.common.config.zero_knowledge = true;
    rejected(
        &circuit,
        options,
        limit,
        "GPU wire blinding is not implemented",
    );
    circuit.common.config.zero_knowledge = false;
    circuit.common.num_lookup_polys = 1;
    rejected(
        &circuit,
        options,
        limit,
        "GPU lookup witnesses are not implemented",
    );
    circuit.common.num_lookup_polys = 0;
    circuit.common.public_initial_degree_bits += 1;
    circuit.common.fri_params.degree_bits += 1;
    rejected(
        &circuit,
        options,
        limit,
        "GPU degree lifting is not implemented",
    );
    circuit.common.public_initial_degree_bits -= 1;
    circuit.common.fri_params.degree_bits -= 1;
    let factor = circuit.common.quotient_degree_factor;
    circuit.common.quotient_degree_factor = 0;
    rejected(&circuit, options, limit, "quotient degree factor is zero");
    circuit.common.quotient_degree_factor = factor;
    let saved_map = circuit.prover_only.representative_map.clone();
    circuit
        .prover_only
        .representative_map
        .truncate(circuit.common.degree() * circuit.common.config.num_wires - 1);
    rejected(
        &circuit,
        options,
        limit,
        "incomplete circuit representative map",
    );
    circuit.prover_only.representative_map = saved_map;
    let first = circuit.prover_only.representative_map[0];
    circuit.prover_only.representative_map[0] = circuit.prover_only.representative_map.len();
    rejected(
        &circuit,
        options,
        limit,
        "invalid circuit representative indices",
    );
    circuit.prover_only.representative_map[0] = first;
    rejected(
        &circuit,
        options,
        circuit.prover_only.representative_map.len() as u64 * 8 - 1,
        "partition witness exceeds storage-binding limit",
    );
    circuit.verifier_only.constants_sigmas_cap.0[0].elements[0] += F::ONE;
    rejected(
        &circuit,
        options,
        limit,
        "fixed oracle does not match circuit metadata",
    );
    circuit.verifier_only.constants_sigmas_cap.0[0].elements[0] -= F::ONE;
    circuit.common.num_constants += 1;
    rejected(
        &circuit,
        options,
        limit,
        "fixed oracle does not match circuit metadata",
    );
    circuit.common.num_constants -= 1;
    let coefficient = circuit.prover_only.constants_sigmas_commitment.polynomials[0]
        .coeffs
        .pop()
        .unwrap();
    rejected(
        &circuit,
        options,
        limit,
        "fixed oracle polynomial shape mismatch",
    );
    circuit.prover_only.constants_sigmas_commitment.polynomials[0]
        .coeffs
        .push(coefficient);
    let leaf = circuit
        .prover_only
        .constants_sigmas_commitment
        .merkle_tree
        .leaves
        .pop()
        .unwrap();
    rejected(&circuit, options, limit, "fixed oracle domain mismatch");
    circuit
        .prover_only
        .constants_sigmas_commitment
        .merkle_tree
        .leaves
        .push(leaf);
    assert!(CircuitLayout::new(&circuit, options, limit).is_ok());
}

#[test]
fn column_batches_respect_binding_limits() {
    assert_eq!(
        column_capacity(1024, 143, 1024 * 8 * 17, usize::MAX).unwrap(),
        17
    );
    assert_eq!(batches(53, 17), [17, 17, 17, 2]);
    assert_eq!(column_capacity(1024, 143, 1024 * 8 * 17, 2).unwrap(), 2);
    assert!(column_capacity(1024, 143, 8191, 17).is_err());
    assert!(column_capacity(1024, 143, 8192, 0).is_err());
    assert!(column_capacity(0, 143, 8192, 1).is_err());
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn resident_wire_commitment_matches_cpu_and_reuses_preparation() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let (circuit, input) = tiny_circuit();
    let prepared = PreparedCircuit::prepare(
        &context,
        &circuit,
        PreparationOptions {
            max_columns_per_batch: 17,
            commitment_chunk_rows: 4,
            quotient_chunk_rows: 4,
        },
    )?;
    let fixed = prepared.fixed_commitment();
    let oracle = &circuit.prover_only.constants_sigmas_commitment;
    let expected_tree = oracle
        .merkle_tree
        .digests
        .iter()
        .chain(&oracle.merkle_tree.cap.0)
        .flat_map(|hash| hash.elements)
        .collect::<Vec<_>>();
    assert_eq!(context.readback(&fixed.tree)?, expected_tree);
    let fixed_evaluations = fixed
        .evaluations
        .iter()
        .map(|batch| context.readback(batch))
        .collect::<Result<Vec<_>>>()?
        .concat();
    let expected_fixed = (0..oracle.polynomials.len())
        .flat_map(|column| {
            (0..prepared.evaluation_rows()).map(move |row| oracle.get_lde_values(row, 1)[column])
        })
        .collect::<Vec<_>>();
    assert_eq!(fixed_evaluations, expected_fixed);
    let fixed_coefficients = fixed
        .coefficients
        .iter()
        .map(|batch| context.readback(batch))
        .collect::<Result<Vec<_>>>()?
        .concat();
    assert_eq!(
        fixed_coefficients,
        oracle
            .polynomials
            .iter()
            .flat_map(|p| p.coeffs.iter().copied())
            .collect::<Vec<_>>()
    );
    // One workspace holds a prefix allocation, all wire buffers, and another
    // stage's output. The consumer binds the resident coefficients directly.
    let mut counts = vec![1];
    counts.extend_from_slice(prepared.wire_workspace_field_counts());
    let consumer_index = counts.len();
    let consumer_len = prepared.wire_workspace_field_counts()[2];
    counts.push(consumer_len);
    let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
    assert!(prepared.wire_buffers(&workspace, 0).is_err());
    let wires = prepared.wire_buffers(&workspace, 1)?;
    let consumer_output = workspace.buffer(consumer_index)?;
    let consumer = ArithmeticPlan::prepare(
        &context,
        Arc::new(ArithmeticKernels::prepare(&context)?),
        consumer_len,
        FieldOperation::Square,
    )?;
    assert_eq!(
        prepared.witness_upload_bytes(),
        circuit.prover_only.representative_map.len() as u64 * 8
    );
    for value in [F::from_canonical_u64(7), F::NEG_ONE] {
        let mut inputs = PartialWitness::new();
        inputs.set_target(input, value)?;
        // With rand enabled the builder adds randomized padding generators.
        // Both commitment implementations must receive the same completed
        // witness, not two independently generated random witnesses.
        let partition = generate_partial_witness(inputs, &circuit.prover_only, &circuit.common)?;
        let cpu_witness = partition.clone().full_witness();
        let wire_values = (0..circuit.common.config.num_wires)
            .map(|column| {
                (0..prepared.degree())
                    .map(|row| cpu_witness.get_wire(row, column))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let expected_values = wire_values.concat();
        let cpu = PolynomialBatch::<F, C, 2>::from_values(
            wire_values.into_iter().map(PolynomialValues::new).collect(),
            circuit.common.config.fri_config.rate_bits,
            false,
            circuit.common.config.fri_config.cap_height,
            &mut TimingTree::default(),
            circuit.prover_only.fft_root_table.as_ref(),
        );
        let mut encoder = workspace.begin(&context)?;
        let commitment = wires.encode_generated(&mut encoder, partition)?;
        consumer.encode(&mut encoder, &commitment.coefficients[0], &consumer_output)?;
        encoder.submit()?.finish()?;
        assert_eq!(commitment.public_inputs, [value * value]);
        let mut gathered = Vec::new();
        for batch in &commitment.wire_values {
            gathered.extend(context.readback(batch)?);
        }
        assert_eq!(gathered, expected_values);
        let coefficients = commitment
            .coefficients
            .iter()
            .map(|batch| context.readback(batch))
            .collect::<Result<Vec<_>>>()?
            .concat();
        assert_eq!(
            coefficients,
            cpu.polynomials
                .iter()
                .flat_map(|p| p.coeffs.iter().copied())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            context.readback(&consumer_output)?,
            cpu.polynomials
                .iter()
                .take(prepared.layout.batch_columns[0])
                .flat_map(|p| p.coeffs.iter().map(|&value| value * value))
                .collect::<Vec<_>>()
        );
        let evaluations = commitment
            .evaluations
            .iter()
            .map(|batch| context.readback(batch))
            .collect::<Result<Vec<_>>>()?
            .concat();
        let expected_evaluations = (0..cpu.polynomials.len())
            .flat_map(|column| {
                (0..prepared.evaluation_rows())
                    .map(|row| cpu.get_lde_values(row, 1)[column])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(evaluations, expected_evaluations);
        let expected_tree = cpu
            .merkle_tree
            .digests
            .iter()
            .chain(&cpu.merkle_tree.cap.0)
            .flat_map(|hash| hash.elements)
            .collect::<Vec<_>>();
        assert_eq!(context.readback(&commitment.tree)?, expected_tree);
        assert_eq!(
            context.readback(&commitment.cap)?,
            cpu.merkle_tree
                .cap
                .0
                .iter()
                .flat_map(|hash| hash.elements)
                .collect::<Vec<_>>()
        );
    }
    // Missing generator inputs must fail before any GPU submission; the same
    // workspace remains reusable rather than being poisoned by admission failure.
    let mut encoder = workspace.begin(&context)?;
    assert!(wires.encode(&mut encoder, PartialWitness::new()).is_err());
    drop(encoder);
    let mut inputs = PartialWitness::new();
    inputs.set_target(input, F::ONE)?;
    let commitment = {
        let mut encoder = workspace.begin(&context)?;
        let commitment = wires.encode(&mut encoder, inputs)?;
        let _pending = encoder.submit()?;
        commitment
    };
    // The caller owns the workspace and can recover after dropping its token.
    workspace.wait(&context)?;
    assert_eq!(commitment.public_inputs, [F::ONE]);
    let mut encoder = workspace.begin(&context)?;
    consumer.encode(&mut encoder, &commitment.coefficients[0], &consumer_output)?;
    encoder.submit()?.finish()?;
    let mut foreign_workspace = ProofWorkspace::prepare(&context, &counts)?;
    let mut foreign_encoder = foreign_workspace.begin(&context)?;
    let mut inputs = PartialWitness::new();
    inputs.set_target(input, F::ONE)?;
    let error = wires
        .encode(&mut foreign_encoder, inputs)
        .err()
        .expect("another workspace must be rejected");
    assert_eq!(
        error.to_string(),
        "buffer belongs to another proof workspace"
    );
    Ok(())
}
