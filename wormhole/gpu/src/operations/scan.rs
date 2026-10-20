use super::{read, table_size, write, FIELD};
use crate::runtime::{FieldBinding, KernelParams, PreparedKernel};
use crate::{DeviceContext, DeviceFieldSlice, FieldSource, ProofEncoder};
use anyhow::{ensure, Result};

const BLOCK: usize = 256;

/// Exclusive products of independent column-major sequences. Workgroup scans
/// are joined by recursively scanning their block totals; no thread traverses
/// the full trace. Zero factors have ordinary multiplication semantics.
pub struct PrefixProductPlan {
    rows: usize,
    columns: usize,
    scan: PreparedKernel,
    carry: PreparedKernel,
    levels: Vec<(usize, usize, KernelParams)>,
    scratch_counts: Vec<usize>,
}

impl PrefixProductPlan {
    pub fn prepare(context: &DeviceContext, rows: usize, columns: usize) -> Result<Self> {
        table_size(rows, columns)?;
        ensure!(
            rows.div_ceil(BLOCK) <= context.limits().max_compute_workgroups_per_dimension as usize
                && columns <= context.limits().max_compute_workgroups_per_dimension as usize
                && context.limits().max_compute_invocations_per_workgroup >= BLOCK as u32,
            "prefix product exceeds dispatch limits"
        );
        let scan = PreparedKernel::prepare_entry(
            context,
            &format!(
                "{FIELD}\n{}",
                include_str!("../shaders/prefix_product.wgsl")
            ),
            &[write(1), read(1), write(1)],
            "prefix product block scan",
            "scan",
            true,
        )?;
        let carry = PreparedKernel::prepare_entry(
            context,
            &format!("{FIELD}\n{}", include_str!("../shaders/prefix_carry.wgsl")),
            &[write(1), read(1)],
            "prefix product block carry",
            "main",
            true,
        )?;
        let mut levels = Vec::new();
        let mut scratch_counts = Vec::new();
        let mut size = rows;
        loop {
            let blocks = size.div_ceil(BLOCK);
            levels.push((
                size,
                blocks,
                context.prepare_params([size as u32, blocks as u32, columns as u32, 0])?,
            ));
            scratch_counts.push(table_size(blocks, columns)?);
            if blocks == 1 {
                break;
            }
            scratch_counts.push(table_size(blocks, columns)?);
            size = blocks;
        }
        Ok(Self {
            rows,
            columns,
            scan,
            carry,
            levels,
            scratch_counts,
        })
    }

    /// Block totals and their exclusive prefixes, from largest to smallest.
    pub fn workspace_field_counts(&self) -> &[usize] {
        &self.scratch_counts
    }

    pub fn encode<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        input: impl Into<FieldSource<'a>>,
        output: &DeviceFieldSlice,
        scratch: &[DeviceFieldSlice],
    ) -> Result<()> {
        let input = input.into();
        ensure!(
            input.len() == self.rows * self.columns
                && output.len() == input.len()
                && scratch.len() == self.scratch_counts.len()
                && scratch
                    .iter()
                    .zip(&self.scratch_counts)
                    .all(|(buffer, &len)| buffer.len() == len),
            "prefix product buffer shape mismatch"
        );
        for (level, &(_, blocks, ref params)) in self.levels.iter().enumerate() {
            let source = if level == 0 {
                input
            } else {
                (&scratch[2 * (level - 1)]).into()
            };
            let destination = if level == 0 {
                output
            } else {
                &scratch[2 * level - 1]
            };
            let bindings = encoder.bind_with_params(
                &self.scan,
                &[
                    FieldBinding::ReadWrite(destination),
                    FieldBinding::Read(source),
                    FieldBinding::ReadWrite(&scratch[2 * level]),
                ],
                Some(params),
                "prefix product block scan",
            )?;
            encoder.dispatch(
                &self.scan,
                &bindings,
                [blocks as u32, self.columns as u32, 1],
                "prefix product block scan",
            )?;
        }
        for level in (0..self.levels.len() - 1).rev() {
            let (rows, _, params) = &self.levels[level];
            let destination = if level == 0 {
                output
            } else {
                &scratch[2 * level - 1]
            };
            let bindings = encoder.bind_with_params(
                &self.carry,
                &[
                    FieldBinding::ReadWrite(destination),
                    FieldBinding::Read((&scratch[2 * level + 1]).into()),
                ],
                Some(params),
                "prefix product block carry",
            )?;
            encoder.dispatch_elements(
                &self.carry,
                &bindings,
                rows * self.columns,
                "prefix product block carry",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
