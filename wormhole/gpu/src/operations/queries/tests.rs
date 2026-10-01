use super::*;
use crate::ProofWorkspace;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::util::reverse_index_bits_in_place;

#[test]
fn query_layout_decodes_cpu_records_and_rejects_invalid_shapes() -> Result<()> {
    let layout = MerkleQueryLayout::new(8, 2, 2, 2, 0)?;
    let values = (0..12).map(F::from_canonical_usize).collect::<Vec<_>>();
    let queries = layout.decode(&values)?;
    assert_eq!(queries[0].0, values[..2]);
    assert_eq!(
        queries[0].1.siblings[0].elements,
        [values[2], values[3], values[4], values[5]]
    );
    assert_eq!(queries[1].0, values[6..8]);
    assert!(layout.decode(&values[..11]).is_err());
    for (rows, width, cap, count, shift) in [
        (0, 1, 0, 1, 0),
        (3, 1, 0, 1, 0),
        (8, 0, 0, 1, 0),
        (8, 1, 4, 1, 0),
        (8, 1, 0, 0, 0),
        (8, 1, 0, 1, 64),
        (8, 1, 0, usize::MAX, 0),
    ] {
        assert!(MerkleQueryLayout::new(rows, width, cap, count, shift).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn sparse_initial_and_fri_queries_match_cpu_leaves_and_paths() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let kernels = Arc::new(MerkleQueryKernels::prepare(&context)?);
    let challenges = [
        F::ZERO,
        F::ONE,
        F::NEG_ONE,
        F::from_canonical_usize(511),
        F::from_canonical_usize(512),
        F::from_canonical_u64((1u64 << 32) + 3),
        F::ONE,
    ];
    for (rows, arity, width, cap, shift) in [(512, 1, 5, 2, 0), (128, 4, 8, 2, 2), (1, 1, 2, 0, 0)]
    {
        let layout = MerkleQueryLayout::new(rows, width, cap, challenges.len(), shift)?;
        let columns = if width == 5 {
            vec![2, 2, 1]
        } else {
            vec![width]
        };
        let plan = if width == 5 {
            MerkleQueryPlan::prepare_columns(&context, kernels.clone(), layout, &columns)?
        } else {
            MerkleQueryPlan::prepare_extension(&context, kernels.clone(), layout, arity)?
        };
        let values = (0..rows * width)
            .map(|i| -F::from_canonical_usize(i + 1))
            .collect::<Vec<_>>();
        let leaves = if width == 5 {
            let mut natural = (0..rows)
                .map(|row| {
                    (0..width)
                        .map(|column| values[column * rows + row])
                        .collect()
                })
                .collect::<Vec<Vec<F>>>();
            reverse_index_bits_in_place(&mut natural);
            natural
        } else {
            let n = rows * arity;
            let mut natural = (0..n)
                .map(|row| [values[row], values[n + row]])
                .collect::<Vec<_>>();
            reverse_index_bits_in_place(&mut natural);
            natural
                .chunks(arity)
                .map(|chunk| chunk.iter().flatten().copied().collect())
                .collect()
        };
        let tree = MerkleTree::<F, PoseidonHash>::new(leaves, cap);
        let packed = tree
            .digests
            .iter()
            .chain(&tree.cap.0)
            .flat_map(|digest| digest.elements)
            .collect::<Vec<_>>();
        let mut counts = columns
            .iter()
            .map(|&count| count * rows)
            .collect::<Vec<_>>();
        let cfirst = counts.len();
        counts.extend([challenges.len(), packed.len(), layout.field_count()]);
        let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
        let buffers = (0..counts.len())
            .map(|i| workspace.buffer(i))
            .collect::<Result<Vec<_>>>()?;
        let short_params = context.prepare_params([0; 4])?;
        let mut encoder = workspace.begin(&context)?;
        assert_eq!(
            encoder
                .bind_with_params(
                    &kernels.columns,
                    &[
                        FieldBinding::ReadWrite(&buffers[cfirst + 2]),
                        FieldBinding::Read((&buffers[cfirst]).into()),
                        FieldBinding::Read((&buffers[0]).into()),
                    ],
                    Some(&short_params),
                    "invalid query parameters",
                )
                .err()
                .unwrap()
                .to_string(),
            "kernel parameter size mismatch"
        );
        let mut offset = 0;
        for (buffer, &columns) in buffers.iter().zip(&columns) {
            encoder.upload(buffer, &values[offset..offset + columns * rows])?;
            offset += columns * rows;
        }
        encoder.upload(&buffers[cfirst], &challenges)?;
        encoder.upload(&buffers[cfirst + 1], &packed)?;
        let gathered = plan.encode(
            &mut encoder,
            &buffers[cfirst],
            &buffers[..cfirst]
                .iter()
                .map(FieldSource::from)
                .collect::<Vec<_>>(),
            (&buffers[cfirst + 1]).into(),
            &buffers[cfirst + 2],
        )?;
        encoder.submit()?.finish()?;
        let expected = challenges
            .iter()
            .map(|challenge| {
                let index = ((challenge.to_canonical_u64() >> shift) & (rows as u64 - 1)) as usize;
                (tree.get(index).to_vec(), tree.prove(index))
            })
            .collect::<Vec<_>>();
        assert_eq!(gathered.readback(&context)?, expected);
    }
    Ok(())
}
