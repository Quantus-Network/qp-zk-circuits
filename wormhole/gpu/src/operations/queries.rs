use super::{read, table_size, write};
use crate::runtime::{FieldBinding, KernelParams, PreparedKernel};
use crate::{DeviceContext, DeviceFieldSlice, FieldSource, ProofEncoder};
use anyhow::{ensure, Context, Result};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::poseidon::PoseidonHash;
use std::sync::Arc;

/// One sampled leaf and its bottom-up sibling path, in the CPU proof format.
pub type MerkleQuery = (Vec<F>, MerkleProof<F, PoseidonHash>);

/// Host-only query record metadata. Indices are canonical challenge modulo the
/// initial domain, then shifted by cumulative FRI reduction bits.
#[derive(Clone, Copy)]
pub struct MerkleQueryLayout {
    rows: usize,
    width: usize,
    count: usize,
    depth: usize,
    shift: usize,
    fields: usize,
    tree_fields: usize,
}

impl MerkleQueryLayout {
    pub fn new(
        rows: usize,
        width: usize,
        cap_height: usize,
        count: usize,
        shift: usize,
    ) -> Result<Self> {
        ensure!(
            rows.is_power_of_two() && cap_height <= rows.ilog2() as usize && shift < 64,
            "invalid Merkle query shape"
        );
        table_size(rows, width)?;
        let depth = rows.ilog2() as usize - cap_height;
        let stride = width
            .checked_add(depth * 4)
            .context("Merkle query stride overflow")?;
        let fields = table_size(count, stride)?;
        let caps = 1usize << cap_height;
        let nodes = rows
            .checked_mul(2)
            .context("Merkle query tree size overflow")?
            - caps;
        let tree_fields = table_size(nodes, 4)?;
        Ok(Self {
            rows,
            width,
            count,
            depth,
            shift,
            fields,
            tree_fields,
        })
    }

    pub fn field_count(&self) -> usize {
        self.fields
    }
    pub fn query_count(&self) -> usize {
        self.count
    }

    pub(crate) fn validate_limit(&self, limit: u64) -> Result<()> {
        ensure!(
            self.fields as u64 * 8 <= limit && self.tree_fields as u64 * 8 <= limit,
            "Merkle query buffers exceed storage-binding limit"
        );
        Ok(())
    }

    pub fn decode(&self, values: &[F]) -> Result<Vec<MerkleQuery>> {
        ensure!(
            values.len() == self.fields,
            "Merkle query result shape mismatch"
        );
        Ok(values
            .chunks_exact(self.width + 4 * self.depth)
            .map(|record| {
                (
                    record[..self.width].to_vec(),
                    MerkleProof {
                        siblings: record[self.width..]
                            .chunks_exact(4)
                            .map(|digest| HashOut {
                                elements: digest.try_into().unwrap(),
                            })
                            .collect(),
                    },
                )
            })
            .collect())
    }
}

/// Shared sparse leaf/path gathering pipelines. No full oracle is read back.
pub struct MerkleQueryKernels {
    columns: PreparedKernel,
    extension: PreparedKernel,
    paths: PreparedKernel,
}

impl MerkleQueryKernels {
    pub fn prepare(context: &DeviceContext) -> Result<Self> {
        let source = include_str!("../shaders/merkle_queries.wgsl");
        let specs = [write(1), read(1), read(1)];
        let prepare = |entry, label| {
            PreparedKernel::prepare_entry_with_params(context, source, &specs, label, entry, 8)
        };
        Ok(Self {
            columns: prepare("columns", "initial oracle query values")?,
            extension: prepare("extension", "FRI query values")?,
            paths: prepare("paths", "Merkle query paths")?,
        })
    }
}

pub struct MerkleQueryPlan {
    kernels: Arc<MerkleQueryKernels>,
    layout: MerkleQueryLayout,
    input_fields: Vec<usize>,
    params: Vec<KernelParams>,
    extension: bool,
}

impl MerkleQueryPlan {
    pub fn prepare_columns(
        context: &DeviceContext,
        kernels: Arc<MerkleQueryKernels>,
        layout: MerkleQueryLayout,
        columns: &[usize],
    ) -> Result<Self> {
        ensure!(
            !columns.is_empty()
                && columns.iter().all(|&n| n > 0)
                && columns
                    .iter()
                    .try_fold(0usize, |sum, &n| sum.checked_add(n))
                    == Some(layout.width),
            "Merkle query column batches do not match leaf width"
        );
        Self::prepare(context, kernels, layout, columns, 1, false)
    }

    pub fn prepare_extension(
        context: &DeviceContext,
        kernels: Arc<MerkleQueryKernels>,
        layout: MerkleQueryLayout,
        arity: usize,
    ) -> Result<Self> {
        ensure!(
            arity.is_power_of_two() && arity.checked_mul(2) == Some(layout.width),
            "FRI query leaf width mismatch"
        );
        table_size(layout.rows, arity * 2)?;
        Self::prepare(context, kernels, layout, &[layout.width], arity, true)
    }

    fn prepare(
        context: &DeviceContext,
        kernels: Arc<MerkleQueryKernels>,
        layout: MerkleQueryLayout,
        columns: &[usize],
        arity: usize,
        extension: bool,
    ) -> Result<Self> {
        layout.validate_limit(
            context
                .limits()
                .max_buffer_size
                .min(u64::from(context.limits().max_storage_buffer_binding_size)),
        )?;
        let mut first = 0;
        let mut params = Vec::new();
        let mut input_fields = Vec::new();
        for &count in columns {
            input_fields.push(table_size(layout.rows, count)?);
            params.push(context.prepare_params([
                layout.rows as u32,
                layout.width as u32,
                layout.depth as u32,
                layout.count as u32,
                layout.shift as u32,
                first as u32,
                count as u32,
                arity as u32,
            ])?);
            first += count;
        }
        Ok(Self {
            kernels,
            layout,
            input_fields,
            params,
            extension,
        })
    }

    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        challenges: &DeviceFieldSlice,
        sources: &[FieldSource<'_>],
        tree: FieldSource<'_>,
        output: &DeviceFieldSlice,
    ) -> Result<ResidentMerkleQueries> {
        ensure!(
            challenges.len() == self.layout.count
                && output.len() == self.layout.fields
                && tree.len() == self.layout.tree_fields
                && sources.len() == self.input_fields.len()
                && sources
                    .iter()
                    .zip(&self.input_fields)
                    .all(|(source, &count)| source.len() == count),
            "Merkle query buffer shape mismatch"
        );
        let kernel = if self.extension {
            &self.kernels.extension
        } else {
            &self.kernels.columns
        };
        for (source, params) in sources.iter().zip(&self.params) {
            let bindings = encoder.bind_with_params(
                kernel,
                &[
                    FieldBinding::ReadWrite(output),
                    FieldBinding::Read(challenges.into()),
                    FieldBinding::Read(*source),
                ],
                Some(params),
                "query leaf gathering",
            )?;
            encoder.dispatch_elements(
                kernel,
                &bindings,
                self.layout.count,
                "query leaf gathering",
            )?;
        }
        let bindings = encoder.bind_with_params(
            &self.kernels.paths,
            &[
                FieldBinding::ReadWrite(output),
                FieldBinding::Read(challenges.into()),
                FieldBinding::Read(tree),
            ],
            Some(&self.params[0]),
            "query path gathering",
        )?;
        encoder.dispatch_elements(
            &self.kernels.paths,
            &bindings,
            self.layout.count,
            "query path gathering",
        )?;
        Ok(ResidentMerkleQueries {
            values: output.clone(),
            layout: self.layout,
        })
    }
}

/// Sampled proof records. Views pin allocations and are overwritten on reuse.
pub struct ResidentMerkleQueries {
    pub values: DeviceFieldSlice,
    pub layout: MerkleQueryLayout,
}

impl ResidentMerkleQueries {
    /// Explicit export after completion; only sampled leaves and paths leave GPU.
    pub fn readback(&self, context: &DeviceContext) -> Result<Vec<MerkleQuery>> {
        self.layout.decode(&context.readback(&self.values)?)
    }
}

#[cfg(test)]
mod tests;
