use super::*;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;

#[test]
fn opening_layout_matches_cpu_and_rejects_changed_protocol_structure() -> Result<()> {
    let circuit =
        CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config()).build::<C>();
    let common = &circuit.common;
    let layout = OpeningLayout::new(common)?;
    assert_eq!(
        layout.all(),
        common.get_fri_instance(E::ONE).batches[0].openings.len()
    );
    assert_eq!(layout.next, common.config.num_challenges);
    let mut instance = common.get_fri_instance(E::ONE);
    instance.oracles[0].num_polys += 1;
    assert_eq!(
        OpeningLayout::from_instance(common, instance)
            .err()
            .unwrap()
            .to_string(),
        "unsupported FRI opening oracle structure"
    );
    let mut instance = common.get_fri_instance(E::ONE);
    instance.batches[1].point = E::ZERO;
    assert_eq!(
        OpeningLayout::from_instance(common, instance)
            .err()
            .unwrap()
            .to_string(),
        "unsupported FRI opening points"
    );
    let mut instance = common.get_fri_instance(E::ONE);
    instance.batches[0].openings.pop();
    assert_eq!(
        OpeningLayout::from_instance(common, instance)
            .err()
            .unwrap()
            .to_string(),
        "unsupported FRI opening batch width"
    );
    let mut instance = common.get_fri_instance(E::ONE);
    instance.batches[0].openings.swap(0, 1);
    assert_eq!(
        OpeningLayout::from_instance(common, instance)
            .err()
            .unwrap()
            .to_string(),
        "unsupported FRI opening expression or order"
    );
    let mut instance = common.get_fri_instance(E::ONE);
    instance.batches[0].openings[0].terms[0].coefficient = FriCoefficient::PointPower(1);
    assert_eq!(
        OpeningLayout::from_instance(common, instance)
            .err()
            .unwrap()
            .to_string(),
        "unsupported FRI opening expression or order"
    );
    Ok(())
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn next_row_openings_and_composition_span_coefficient_batches() -> Result<()> {
    use plonky2::field::polynomial::PolynomialCoeffs;
    use plonky2::util::reducing::ReducingFactor;

    let context = futures::executor::block_on(DeviceContext::new())?;
    let mut config = CircuitConfig::standard_recursion_config();
    config.num_challenges = 3;
    let circuit = CircuitBuilder::<F, 2>::new(config).build::<C>();
    let prepared = PreparedCircuit::prepare(
        &context,
        &circuit,
        PreparationOptions {
            max_columns_per_batch: 2,
            ..Default::default()
        },
    )?;
    let plan = &prepared.openings;
    assert_eq!(plan.next.len(), 2);
    assert_eq!(plan.next[0].columns, 2);
    assert_eq!(plan.next[1].columns, 1);
    assert_eq!(plan.next[1].first_opening, plan.layout.all() + 2);
    let degree = prepared.degree();
    let polynomials = (0..plan.layout.all())
        .map(|column| {
            PolynomialCoeffs::new(
                (0..degree)
                    .map(|row| -F::from_canonical_usize(1 + row + column * degree))
                    .collect(),
            )
            .to_extension::<2>()
        })
        .collect::<Vec<_>>();
    let mut counts = plan
        .all
        .iter()
        .map(|batch| batch.columns * degree)
        .collect::<Vec<_>>();
    let first = counts.len();
    counts.extend_from_slice(prepared.opening_workspace_field_counts());
    let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
    let sources = (0..first)
        .map(|index| workspace.buffer(index))
        .collect::<Result<Vec<_>>>()?;
    let buffers = prepared.opening_buffers(&workspace, first)?;
    let zeta = QuadraticExtension([F::from_canonical_u64(11), F::from_canonical_u64(9)]);
    let alpha = QuadraticExtension([F::from_canonical_u64(17), F::from_canonical_u64(23)]);
    let g = E::primitive_root_of_unity(circuit.common.degree_bits());
    let mut encoder = workspace.begin(&context)?;
    for (batch, source) in plan.all.iter().zip(&sources) {
        let values = polynomials[batch.first_opening..batch.first_opening + batch.columns]
            .iter()
            .flat_map(|p| p.coeffs.iter().map(|coefficient| coefficient.0[0]))
            .collect::<Vec<_>>();
        encoder.upload(source, &values)?;
    }
    let openings = buffers.encode_sources(
        &mut encoder,
        sources.iter().map(FieldSource::from).collect(),
        zeta,
    )?;
    // No transcript is needed for this focused oracle; alpha is fixed.
    let input = buffers.encode_fri_input(&mut encoder, &openings, alpha)?;
    encoder.submit()?.finish()?;
    let zs_start = plan.layout.widths[0] + plan.layout.widths[1];
    let next = &polynomials[zs_start..zs_start + plan.layout.next];
    let expected = polynomials
        .iter()
        .map(|p| p.eval(zeta))
        .chain(next.iter().map(|p| p.eval(g * zeta)))
        .flat_map(|value| value.0)
        .collect::<Vec<_>>();
    assert_eq!(context.readback(&openings.values)?, expected);
    let mut reducer = ReducingFactor::new(alpha);
    let mut combined = PolynomialCoeffs::empty();
    for (batch, point) in [(&polynomials[..], zeta), (next, g * zeta)] {
        let mut quotient = reducer.reduce_polys(batch.iter()).divide_by_linear(point);
        quotient.coeffs.push(E::ZERO);
        reducer.shift_poly(&mut combined);
        combined += quotient;
    }
    assert_eq!(
        context.readback(&input.coefficients)?,
        (0..2)
            .flat_map(|component| combined.coeffs.iter().map(move |value| value.0[component]))
            .collect::<Vec<_>>()
    );
    Ok(())
}
