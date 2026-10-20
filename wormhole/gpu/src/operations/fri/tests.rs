use super::*;
use crate::ProofWorkspace;
use plonky2::field::extension::quadratic::QuadraticExtension as E;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::plonk_common::reduce_with_powers;
use plonky2::util::reverse_index_bits_in_place;

#[test]
fn fri_folding_shapes_reject_invalid_or_unaddressable_tables() {
    for (degree, arity) in [(0, 2), (3, 2), (8, 0), (8, 3), (8, 16)] {
        assert!(validate_fold(degree, arity).is_err());
    }
    for arity in [1, 2, 4, 8] {
        validate_fold(8, arity).unwrap();
    }
    assert!(validate_fold(u32::MAX as usize, 1).is_err());
}

fn planes(values: &[E<F>]) -> Vec<F> {
    (0..2)
        .flat_map(|component| values.iter().map(move |value| value.0[component]))
        .collect()
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn fri_folds_and_chunked_commitments_match_cpu() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let kernels = Arc::new(FriKernels::prepare(&context)?);
    let poseidon = Arc::new(PoseidonKernels::prepare(&context)?);
    for (rows, arity, cap_height) in [
        (1, 1, 0),
        (512, 1, 2),
        (512, 2, 2),
        (512, 4, 0),
        (512, 16, 5),
    ] {
        let values = (0..rows)
            .map(|i| {
                E([
                    if i % 7 == 0 {
                        F::NEG_ONE
                    } else {
                        F::from_canonical_usize(i)
                    },
                    -F::from_canonical_usize(i + 1),
                ])
            })
            .collect::<Vec<_>>();
        let fold = FriFoldPlan::prepare(&context, kernels.clone(), values.len(), arity)?;
        let commitment = FriCommitmentPlan::prepare(
            &context,
            kernels.clone(),
            poseidon.clone(),
            values.len(),
            arity,
            cap_height,
            7,
        )?;
        let mut counts = vec![values.len() * 2, 2, fold.output_field_count()];
        counts.extend(commitment.workspace_field_counts());
        let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
        let buffers = (0..counts.len())
            .map(|i| workspace.buffer(i))
            .collect::<Result<Vec<_>>>()?;
        for beta in [
            E([F::from_canonical_u64(11), F::from_canonical_u64(9)]),
            E::<F>::ZERO,
        ] {
            let mut encoder = workspace.begin(&context)?;
            encoder.upload(&buffers[0], &planes(&values))?;
            encoder.upload(&buffers[1], &beta.0)?;
            assert!(fold
                .encode(&mut encoder, &buffers[0], &buffers[1], &buffers[0])
                .is_err());
            fold.encode(&mut encoder, &buffers[0], &buffers[1], &buffers[2])?;
            commitment.encode(
                &mut encoder,
                &buffers[0],
                &buffers[3],
                &buffers[4],
                &buffers[5],
            )?;
            encoder.submit()?.finish()?;
            let expected = values
                .chunks_exact(arity)
                .map(|chunk| reduce_with_powers(chunk, beta))
                .collect::<Vec<_>>();
            assert_eq!(context.readback(&buffers[2])?, planes(&expected));
            let mut reversed = values.clone();
            reverse_index_bits_in_place(&mut reversed);
            let tree = MerkleTree::<F, PoseidonHash>::new(
                reversed
                    .chunks(arity)
                    .map(|chunk| chunk.iter().flat_map(|value| value.0).collect())
                    .collect(),
                cap_height,
            );
            let expected_tree = tree
                .digests
                .iter()
                .chain(&tree.cap.0)
                .flat_map(|digest| digest.elements)
                .collect::<Vec<_>>();
            assert_eq!(context.readback(&buffers[5])?, expected_tree);
            assert_eq!(
                context.readback(&commitment.cap(&buffers[5])?)?,
                tree.cap
                    .0
                    .iter()
                    .flat_map(|digest| digest.elements)
                    .collect::<Vec<_>>()
            );
            // Packing never modifies the natural-order evaluation source.
            assert_eq!(context.readback(&buffers[0])?, planes(&values));
        }
    }
    Ok(())
}
