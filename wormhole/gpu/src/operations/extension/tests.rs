use super::*;
use crate::ProofWorkspace;
use plonky2::field::extension::quadratic::QuadraticExtension as E;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::field::types::Field;

fn planes(values: &[E<F>]) -> Vec<F> {
    (0..2)
        .flat_map(|component| values.iter().map(move |value| value.0[component]))
        .collect()
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn extension_polynomial_operations_match_cpu_across_block_boundaries() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let kernels = Arc::new(ExtensionKernels::prepare(&context)?);
    let point = E([F::from_canonical_u64(11), F::from_canonical_u64(9)]);
    let weights = [
        E([F::ONE, F::NEG_ONE]),
        E([F::ZERO, F::ONE]),
        E([F::from_canonical_u64(17), F::from_canonical_u64(23)]),
    ];
    // Includes three division-scan levels and two evaluation-reduction levels.
    for degree in [1, 255, 256, 257, 4097, 262145] {
        let columns = 3;
        let evaluation =
            PolynomialEvaluationPlan::prepare(&context, kernels.clone(), degree, columns, 0)?;
        let zero_evaluation =
            PolynomialEvaluationPlan::prepare(&context, kernels.clone(), degree, columns, 1)?;
        let combine = PolynomialCombinationPlan::prepare(
            &context,
            kernels.clone(),
            degree,
            columns,
            0,
            false,
        )?;
        let division = LinearDivisionPlan::prepare(&context, kernels.clone(), degree, 0)?;
        let zero_division = LinearDivisionPlan::prepare(&context, kernels.clone(), degree, 1)?;
        let mut counts = vec![
            degree * columns,
            4,
            6,
            columns * 2,
            columns * 2,
            degree * 2,
            degree * 2,
        ];
        let efirst = counts.len();
        counts.extend_from_slice(evaluation.workspace_field_counts());
        let dfirst = counts.len();
        counts.extend_from_slice(division.workspace_field_counts());
        let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
        let buffers = (0..counts.len())
            .map(|index| workspace.buffer(index))
            .collect::<Result<Vec<_>>>()?;
        let values = (0..degree * columns)
            .map(|i| {
                if i % 19 == 0 {
                    F::NEG_ONE
                } else {
                    F::from_canonical_usize(i % 997)
                }
            })
            .collect::<Vec<_>>();
        let polynomials = values
            .chunks(degree)
            .map(|column| PolynomialCoeffs::new(column.to_vec()))
            .collect::<Vec<_>>();
        let combined = PolynomialCoeffs::new(
            (0..degree)
                .map(|row| {
                    polynomials
                        .iter()
                        .zip(weights)
                        .map(|(p, weight)| weight * E([p.coeffs[row], F::ZERO]))
                        .sum()
                })
                .collect(),
        );
        let mut encoder = workspace.begin(&context)?;
        encoder.upload(&buffers[0], &values)?;
        encoder.upload(&buffers[1], &[point.0[0], point.0[1], F::ZERO, F::ZERO])?;
        encoder.upload(
            &buffers[2],
            &weights
                .into_iter()
                .flat_map(|value| value.0)
                .collect::<Vec<_>>(),
        )?;
        assert!(evaluation
            .encode(
                &mut encoder,
                &buffers[0],
                &buffers[1],
                &buffers[3].slice(0..2)?,
                &buffers[efirst..dfirst]
            )
            .is_err());
        evaluation.encode(
            &mut encoder,
            &buffers[0],
            &buffers[1],
            &buffers[3],
            &buffers[efirst..dfirst],
        )?;
        zero_evaluation.encode(
            &mut encoder,
            &buffers[0],
            &buffers[1],
            &buffers[4],
            &buffers[efirst..dfirst],
        )?;
        combine.encode(&mut encoder, &buffers[0], &buffers[2], &buffers[5])?;
        division.encode(
            &mut encoder,
            &buffers[5],
            &buffers[1],
            &buffers[6],
            &buffers[dfirst..],
        )?;
        encoder.submit()?.finish()?;
        let expected = polynomials
            .iter()
            .map(|p| p.to_extension::<2>().eval(point))
            .flat_map(|value| value.0)
            .collect::<Vec<_>>();
        assert_eq!(
            context.readback(&buffers[3])?,
            expected,
            "evaluation degree={degree}"
        );
        assert_eq!(
            context.readback(&buffers[4])?,
            polynomials
                .iter()
                .flat_map(|p| [p.coeffs[0], F::ZERO])
                .collect::<Vec<_>>()
        );
        assert_eq!(context.readback(&buffers[5])?, planes(&combined.coeffs));
        assert_eq!(
            context.readback(&buffers[6])?,
            planes(&combined.divide_by_linear(point).padded(degree).coeffs),
            "division degree={degree}"
        );
        // Reuse scratch and exercise legal in-place division at point zero.
        let mut encoder = workspace.begin(&context)?;
        zero_division.encode(
            &mut encoder,
            &buffers[5],
            &buffers[1],
            &buffers[5],
            &buffers[dfirst..],
        )?;
        encoder.submit()?.finish()?;
        assert_eq!(
            context.readback(&buffers[5])?,
            planes(
                &combined
                    .divide_by_linear(E::<F>::ZERO)
                    .padded(degree)
                    .coeffs
            )
        );
    }
    Ok(())
}
