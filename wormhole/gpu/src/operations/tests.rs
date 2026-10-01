use super::*;
use crate::{DeviceContext, FieldSource, ProofWorkspace};
use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::{Field, Field64};
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::Poseidon;
use plonky2::hash::poseidon::PoseidonHash;
use std::sync::Arc;

fn samples(n: usize, seed: u64) -> Vec<F> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            F::from_noncanonical_u64(state)
        })
        .collect()
}

#[test]
fn table_addressing_is_checked() {
    assert_eq!(table_size(16, 143).unwrap(), 2288);
    assert!(table_size(0, 143).is_err());
    assert!(table_size(16, 0).is_err());
    assert!(table_size(usize::MAX, 2).is_err());
}

#[test]
fn mds_accumulation_bound_is_checked() {
    use super::commitment::validate_mds;
    assert!(validate_mds(&F::MDS_MATRIX_CIRC, &F::MDS_MATRIX_DIAG).is_ok());
    let mut circ = [0; 12];
    circ[0] = 1 << 32;
    assert!(validate_mds(&circ, &[0; 12]).is_ok());
    assert!(validate_mds(&circ, &[1; 12]).is_err());
    assert!(validate_mds(&[1 << 31; 12], &[0; 12]).is_err());
    assert!(validate_mds(&[u64::MAX; 12], &[u64::MAX; 12]).is_err());
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn goldilocks_arithmetic_matches_cpu_at_boundaries_and_arbitrary_values() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let mut a = samples(64, 7);
    a[..6].copy_from_slice(&[
        F::ZERO,
        F::ONE,
        F::NEG_ONE,
        F::from_canonical_u64(0xffffffff),
        F::from_canonical_u64(0x100000000),
        F::from_canonical_u64(F::ORDER - 2),
    ]);
    let b = a.iter().rev().copied().collect::<Vec<_>>();
    let input = [a.clone(), b.clone()].concat();
    let kernels = Arc::new(ArithmeticKernels::prepare(&context)?);
    let mut workspace = ProofWorkspace::prepare(&context, &[input.len(), a.len()])?;
    let source = workspace.buffer(0)?;
    let output = workspace.buffer(1)?;
    for operation in [
        FieldOperation::Add,
        FieldOperation::Subtract,
        FieldOperation::Multiply,
        FieldOperation::Square,
        FieldOperation::Sbox,
    ] {
        let plan = ArithmeticPlan::prepare(&context, Arc::clone(&kernels), a.len(), operation)?;
        let view = source.slice(0..a.len() * operation.input_columns())?;
        let mut encoder = workspace.begin(&context)?;
        encoder.upload(&source, &input)?;
        plan.encode(&mut encoder, &view, &output)?;
        encoder.submit()?.finish()?;
        let expected = a
            .iter()
            .zip(&b)
            .map(|(&a, &b)| match operation {
                FieldOperation::Add => a + b,
                FieldOperation::Subtract => a - b,
                FieldOperation::Multiply => a * b,
                FieldOperation::Square => a * a,
                FieldOperation::Sbox => a.exp_u64(7),
            })
            .collect::<Vec<_>>();
        assert_eq!(context.readback(&output)?, expected, "{operation:?}");
    }
    Ok(())
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn fft_and_inverse_match_cpu_with_padding_and_cosets() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let kernels = Arc::new(FftKernels::prepare(&context)?);
    for (degree, rows) in [(1, 1), (1, 8), (8, 8), (8, 64), (64, 64)] {
        for shift in [F::ONE, F::coset_shift()] {
            let coeffs = samples(degree * 3, 42);
            let expected = coeffs
                .chunks_exact(degree)
                .flat_map(|column| {
                    let mut padded = column.to_vec();
                    padded.resize(rows, F::ZERO);
                    PolynomialCoeffs::new(padded).coset_fft(shift).values
                })
                .collect::<Vec<_>>();
            let forward =
                FftPlan::prepare_coset(&context, Arc::clone(&kernels), degree, rows, shift)?;
            let inverse = FftPlan::prepare_inverse(&context, Arc::clone(&kernels), rows, shift)?;
            let fixed_input = context.prepare_fixed(&coeffs)?;
            let mut workspace = ProofWorkspace::prepare(&context, &[rows * 3, rows * 3])?;
            let values = workspace.buffer(0)?;
            let recovered = workspace.buffer(1)?;
            let mut encoder = workspace.begin(&context)?;
            forward.encode(&mut encoder, &fixed_input, &values)?;
            inverse.encode(&mut encoder, &values, &recovered)?;
            encoder.submit()?.finish()?;
            assert_eq!(context.readback(&values)?, expected, "FFT {degree}/{rows}");
            let expected_inverse = expected
                .chunks_exact(rows)
                .flat_map(|column| {
                    PolynomialValues::new(column.to_vec())
                        .coset_ifft(shift)
                        .coeffs
                })
                .collect::<Vec<_>>();
            assert_eq!(
                context.readback(&recovered)?,
                expected_inverse,
                "IFFT {degree}/{rows}"
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn poseidon_commitments_match_cpu_layout_caps_and_bit_reversal() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let kernels = Arc::new(PoseidonKernels::prepare(&context)?);
    for width in [1, 7, 8, 9, 17, 143] {
        let rows = 16usize;
        let columns = (0..width)
            .map(|column| samples(rows, column as u64 + 1))
            .collect::<Vec<_>>();
        let fixed = columns
            .iter()
            .map(|values| context.prepare_fixed(values))
            .collect::<Result<Vec<_>>>()?;
        let sources = fixed.iter().map(FieldSource::from).collect::<Vec<_>>();
        for order in [EvaluationOrder::Natural, EvaluationOrder::BitReversed] {
            for cap_height in [0, 2, 4] {
                let plan = CommitmentPlan::prepare_chunked(
                    &context,
                    Arc::clone(&kernels),
                    rows,
                    width,
                    cap_height,
                    order,
                    4,
                )?;
                let mut workspace =
                    ProofWorkspace::prepare(&context, &plan.workspace_field_counts())?;
                let input_chunk = workspace.buffer(0)?;
                let leaf_chunk = workspace.buffer(1)?;
                let tree = workspace.buffer(2)?;
                let mut encoder = workspace.begin(&context)?;
                plan.encode(&mut encoder, &sources, &input_chunk, &leaf_chunk, &tree)?;
                encoder.submit()?.finish()?;
                let leaves = (0..rows)
                    .map(|row| {
                        let index = if order == EvaluationOrder::BitReversed {
                            row.reverse_bits() >> (usize::BITS - rows.ilog2())
                        } else {
                            row
                        };
                        columns.iter().map(|column| column[index]).collect()
                    })
                    .collect();
                let cpu = MerkleTree::<F, PoseidonHash>::new(leaves, cap_height);
                let expected = cpu
                    .digests
                    .iter()
                    .chain(&cpu.cap.0)
                    .flat_map(|digest| digest.elements)
                    .collect::<Vec<_>>();
                assert_eq!(
                    context.readback(&tree)?,
                    expected,
                    "Merkle width {width}, cap {cap_height}, {order:?}"
                );
                assert_eq!(context.readback(&plan.cap(&tree)?)?, cpu.cap.flatten());
            }
        }
    }
    Ok(())
}
