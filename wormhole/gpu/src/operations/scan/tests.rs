use super::*;
use crate::ProofWorkspace;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn hierarchical_prefix_products_match_cpu_including_zeros() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    // The last shape requires three scan levels, not just one carry pass.
    for rows in [1, 255, 256, 257, 65537] {
        let columns = 2;
        let plan = PrefixProductPlan::prepare(&context, rows, columns)?;
        let mut counts = vec![rows * columns; 2];
        counts.extend_from_slice(plan.workspace_field_counts());
        let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
        let input = workspace.buffer(0)?;
        let output = workspace.buffer(1)?;
        let scratch = (2..counts.len())
            .map(|i| workspace.buffer(i))
            .collect::<Result<Vec<_>>>()?;
        let values = (0..rows * columns)
            .map(|i| {
                if i == rows + rows / 2 {
                    F::ZERO
                } else {
                    F::from_canonical_usize(1 + i % 17)
                }
            })
            .collect::<Vec<_>>();
        let expected = values
            .chunks(rows)
            .flat_map(|column| {
                let mut product = F::ONE;
                column.iter().map(move |&value| {
                    let before = product;
                    product *= value;
                    before
                })
            })
            .collect::<Vec<_>>();
        let mut encoder = workspace.begin(&context)?;
        assert!(plan.encode(&mut encoder, &input, &output, &[]).is_err());
        encoder.upload(&input, &values)?;
        plan.encode(&mut encoder, &input, &output, &scratch)?;
        encoder.submit()?.finish()?;
        assert_eq!(context.readback(&output)?, expected, "rows={rows}");
    }
    Ok(())
}
