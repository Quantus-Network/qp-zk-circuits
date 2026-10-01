use super::{read, table_size, write, FIELD};
use crate::runtime::{
    DeviceContext, DeviceFieldSlice, FieldBinding, FieldSource, FixedFieldSlice, KernelParams,
    PreparedKernel, ProofEncoder,
};
use anyhow::{ensure, Result};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::{Poseidon, ALL_ROUND_CONSTANTS};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationOrder {
    Natural,
    BitReversed,
}

/// Plonky2 Poseidon1 pipelines and fast-partial-round tables, shared across
/// commitments. This is deliberately not the miner's Poseidon2 permutation.
pub struct PoseidonKernels {
    leaves: PreparedKernel,
    scatter: PreparedKernel,
    scatter_reversed: PreparedKernel,
    nodes: PreparedKernel,
    circ: FixedFieldSlice,
    diag: FixedFieldSlice,
    constants: FixedFieldSlice,
}

impl PoseidonKernels {
    pub fn prepare(context: &DeviceContext) -> Result<Self> {
        validate_mds(&F::MDS_MATRIX_CIRC, &F::MDS_MATRIX_DIAG)?;
        let mut constants = ALL_ROUND_CONSTANTS[..360].to_vec();
        constants.extend(F::FAST_PARTIAL_FIRST_ROUND_CONSTANT);
        constants.extend(F::FAST_PARTIAL_ROUND_INITIAL_MATRIX.into_iter().flatten());
        constants.extend(F::FAST_PARTIAL_ROUND_CONSTANTS);
        constants.extend(F::FAST_PARTIAL_ROUND_W_HATS.into_iter().flatten());
        constants.extend(F::FAST_PARTIAL_ROUND_VS.into_iter().flatten());
        ensure!(
            constants.len() == 999,
            "unexpected CPU Poseidon constant layout"
        );
        let upload = |values: &[u64]| {
            context.prepare_fixed(
                &values
                    .iter()
                    .copied()
                    .map(F::from_noncanonical_u64)
                    .collect::<Vec<_>>(),
            )
        };
        let circ = upload(&F::MDS_MATRIX_CIRC)?;
        let diag = upload(&F::MDS_MATRIX_DIAG)?;
        let constants = upload(&constants)?;
        let source = format!("{FIELD}\n{}", include_str!("../shaders/poseidon.wgsl"));
        let specs = [write(4), read(1), read(12), read(12), read(999)];
        Ok(Self {
            leaves: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "Poseidon leaves",
                "hash_leaves",
                true,
            )?,
            scatter: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "Merkle leaf placement",
                "scatter_natural",
                true,
            )?,
            scatter_reversed: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "Merkle bit-reversed leaf placement",
                "scatter_leaves",
                true,
            )?,
            nodes: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "Poseidon Merkle nodes",
                "hash_nodes",
                true,
            )?,
            circ,
            diag,
            constants,
        })
    }

    fn bindings<'a>(
        &'a self,
        input: FieldSource<'a>,
        output: &'a DeviceFieldSlice,
    ) -> [FieldBinding<'a>; 5] {
        [
            FieldBinding::ReadWrite(output),
            FieldBinding::Read(input),
            FieldBinding::Read((&self.circ).into()),
            FieldBinding::Read((&self.diag).into()),
            FieldBinding::Read((&self.constants).into()),
        ]
    }
}

pub(super) fn validate_mds(circ: &[u64; 12], diag: &[u64; 12]) -> Result<()> {
    // State lanes can occupy all 64 bits. A row coefficient sum <= 2^32
    // keeps the shader's unreduced dot product strictly below 2^96.
    let sum: u128 = circ.iter().map(|&value| u128::from(value)).sum();
    ensure!(
        diag.iter()
            .all(|&value| sum + u128::from(value) <= 1u128 << 32),
        "Poseidon MDS coefficients exceed the GPU accumulation bound"
    );
    Ok(())
}

/// Hash polynomial columns directly into the CPU's packed sibling-interleaved
/// tree layout. No construction-order tree or second full-tree copy is kept.
/// Chunk scratch bounds storage bindings without requiring a monolithic full
/// evaluation matrix. All packing is GPU-to-GPU copies, not host readback.
pub struct CommitmentPlan {
    kernels: Arc<PoseidonKernels>,
    rows: usize,
    width: usize,
    caps: usize,
    chunk_rows: usize,
    order: EvaluationOrder,
    leaf_params: KernelParams,
    scatter_params: Vec<KernelParams>,
    node_params: Vec<KernelParams>,
}

impl CommitmentPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<PoseidonKernels>,
        rows: usize,
        width: usize,
        cap_height: usize,
        order: EvaluationOrder,
    ) -> Result<Self> {
        Self::prepare_chunked(context, kernels, rows, width, cap_height, order, rows)
    }

    /// Bound per-commitment scratch independently of the device binding limit.
    /// Useful when several commitments coexist in a prepared proof workspace.
    pub fn prepare_chunked(
        context: &DeviceContext,
        kernels: Arc<PoseidonKernels>,
        rows: usize,
        width: usize,
        cap_height: usize,
        order: EvaluationOrder,
        max_chunk_rows: usize,
    ) -> Result<Self> {
        ensure!(
            rows.is_power_of_two() && cap_height <= rows.ilog2() as usize,
            "invalid Merkle shape"
        );
        table_size(rows, width)?;
        let caps = 1usize << cap_height;
        let tree_fields = table_size(2 * rows - caps, 4)?;
        let limit = u64::from(context.limits().max_storage_buffer_binding_size)
            .min(context.limits().max_buffer_size);
        ensure!(
            tree_fields as u64 * 8 <= limit,
            "packed Merkle tree exceeds storage limit"
        );
        ensure!(max_chunk_rows > 0, "commitment chunk limit is zero");
        let capacity = (limit / (width as u64 * 8))
            .min(rows as u64)
            .min(max_chunk_rows as u64) as usize;
        ensure!(capacity > 0, "one commitment row exceeds storage limit");
        let chunk_rows = 1usize << capacity.ilog2();
        let leaf_params = context.prepare_params([chunk_rows as u32, width as u32, 0, 0])?;
        let scatter_params = (0..rows)
            .step_by(chunk_rows)
            .map(|offset| {
                context.prepare_params([chunk_rows as u32, offset as u32, rows as u32, caps as u32])
            })
            .collect::<Result<_>>()?;
        let node_params = (1..=rows.ilog2() - cap_height as u32)
            .map(|level| {
                context.prepare_params([(rows >> level) as u32, level, rows as u32, caps as u32])
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            kernels,
            rows,
            width,
            caps,
            chunk_rows,
            order,
            leaf_params,
            scatter_params,
            node_params,
        })
    }

    /// Field counts for packed input chunk, chunk digests, and the final tree.
    pub fn workspace_field_counts(&self) -> [usize; 3] {
        [
            self.chunk_rows * self.width,
            self.chunk_rows * 4,
            (2 * self.rows - self.caps) * 4,
        ]
    }

    /// The tree suffix is the cap. This view is suitable for explicit export;
    /// the complete tree remains resident for later query gathering.
    pub fn cap(&self, tree: &DeviceFieldSlice) -> Result<DeviceFieldSlice> {
        ensure!(
            tree.len() == self.workspace_field_counts()[2],
            "Merkle tree shape mismatch"
        );
        tree.slice(8 * (self.rows - self.caps)..tree.len())
    }

    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        columns: &[FieldSource<'_>],
        input_chunk: &DeviceFieldSlice,
        leaf_chunk: &DeviceFieldSlice,
        tree: &DeviceFieldSlice,
    ) -> Result<()> {
        let shape = self.workspace_field_counts();
        ensure!(
            columns.len() == self.width && columns.iter().all(|column| column.len() == self.rows),
            "commitment column shape mismatch"
        );
        ensure!(
            [input_chunk.len(), leaf_chunk.len(), tree.len()] == shape,
            "commitment workspace shape mismatch"
        );
        let leaves = encoder.bind_with_params(
            &self.kernels.leaves,
            &self.kernels.bindings(input_chunk.into(), leaf_chunk),
            Some(&self.leaf_params),
            "Poseidon leaves",
        )?;
        let scatter = if self.order == EvaluationOrder::Natural {
            &self.kernels.scatter
        } else {
            &self.kernels.scatter_reversed
        };
        for (chunk, params) in self.scatter_params.iter().enumerate() {
            let offset = chunk * self.chunk_rows;
            for (column, source) in columns.iter().enumerate() {
                let destination =
                    input_chunk.slice(column * self.chunk_rows..(column + 1) * self.chunk_rows)?;
                match source {
                    FieldSource::Fixed(source) => encoder.copy(
                        &source.slice(offset..offset + self.chunk_rows)?,
                        &destination,
                    )?,
                    FieldSource::Workspace(source) => encoder.copy(
                        &source.slice(offset..offset + self.chunk_rows)?,
                        &destination,
                    )?,
                }
            }
            encoder.dispatch_elements(
                &self.kernels.leaves,
                &leaves,
                self.chunk_rows,
                "Poseidon leaves",
            )?;
            let group = encoder.bind_with_params(
                scatter,
                &self.kernels.bindings(leaf_chunk.into(), tree),
                Some(params),
                "Merkle leaf placement",
            )?;
            encoder.dispatch_elements(scatter, &group, self.chunk_rows, "Merkle leaf placement")?;
        }
        for (level, params) in self.node_params.iter().enumerate() {
            let group = encoder.bind_with_params(
                &self.kernels.nodes,
                &self.kernels.bindings(leaf_chunk.into(), tree),
                Some(params),
                "Merkle internal nodes",
            )?;
            encoder.dispatch_elements(
                &self.kernels.nodes,
                &group,
                self.rows >> (level + 1),
                "Merkle internal nodes",
            )?;
        }
        Ok(())
    }
}
