use super::extension::EXTENSION;
use super::{read, table_size, write, CommitmentPlan, EvaluationOrder, PoseidonKernels, FIELD};
use crate::runtime::{FieldBinding, KernelParams, PreparedKernel};
use crate::{DeviceContext, DeviceFieldSlice, ProofEncoder};
use anyhow::{ensure, Result};
use std::sync::Arc;

/// Extension coefficient-folding and FRI leaf-packing pipelines, prepared once.
pub struct FriKernels {
    fold: PreparedKernel,
    pack: PreparedKernel,
}

impl FriKernels {
    pub fn prepare(context: &DeviceContext) -> Result<Self> {
        let source = format!(
            "{FIELD}\n{EXTENSION}\n{}",
            include_str!("../shaders/fri_fold.wgsl")
        );
        Ok(Self {
            fold: PreparedKernel::prepare_entry(
                context,
                &source,
                &[write(2), read(2), read(2)],
                "FRI coefficient folding",
                "fold",
                true,
            )?,
            pack: PreparedKernel::prepare_entry(
                context,
                include_str!("../shaders/fri_pack.wgsl"),
                &[write(1), read(2)],
                "FRI leaf packing",
                "main",
                true,
            )?,
        })
    }
}

/// Reduce arity-sized coefficient groups with successive powers of beta.
/// Input and output use real/extension component planes and may not alias.
/// Known zero LDE padding is omitted, as in the zero-padded FFT operation.
pub struct FriFoldPlan {
    kernels: Arc<FriKernels>,
    coefficients: usize,
    arity: usize,
    params: KernelParams,
}

impl FriFoldPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<FriKernels>,
        coefficients: usize,
        arity: usize,
    ) -> Result<Self> {
        validate_fold(coefficients, arity)?;
        Ok(Self {
            kernels,
            coefficients,
            arity,
            params: context.prepare_params([coefficients as u32, arity as u32, 0, 0])?,
        })
    }

    pub fn output_field_count(&self) -> usize {
        2 * (self.coefficients / self.arity)
    }

    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        coefficients: &DeviceFieldSlice,
        beta: &DeviceFieldSlice,
        output: &DeviceFieldSlice,
    ) -> Result<()> {
        ensure!(
            coefficients.len() == self.coefficients * 2
                && beta.len() == 2
                && output.len() == self.output_field_count(),
            "FRI fold buffer shape mismatch"
        );
        let group = encoder.bind_with_params(
            &self.kernels.fold,
            &[
                FieldBinding::ReadWrite(output),
                FieldBinding::Read(coefficients.into()),
                FieldBinding::Read(beta.into()),
            ],
            Some(&self.params),
            "FRI coefficient folding",
        )?;
        encoder.dispatch_elements(
            &self.kernels.fold,
            &group,
            self.coefficients / self.arity,
            "FRI coefficient folding",
        )
    }
}

pub(crate) fn validate_fold(coefficients: usize, arity: usize) -> Result<()> {
    table_size(coefficients, 2)?;
    ensure!(
        coefficients.is_power_of_two() && arity.is_power_of_two() && arity <= coefficients,
        "invalid FRI folding shape"
    );
    Ok(())
}

/// Commit grouped bit-reversed extension evaluations with the existing Poseidon
/// packed-tree operation. Evaluation planes remain in natural order; reversal
/// happens exactly once while filling bounded leaf chunks.
pub struct FriCommitmentPlan {
    kernels: Arc<FriKernels>,
    evaluations: usize,
    commitment: CommitmentPlan,
    packing_params: Vec<KernelParams>,
}

impl FriCommitmentPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<FriKernels>,
        poseidon: Arc<PoseidonKernels>,
        evaluations: usize,
        arity: usize,
        cap_height: usize,
        max_chunk_rows: usize,
    ) -> Result<Self> {
        validate_fold(evaluations, arity)?;
        let leaves = evaluations / arity;
        let commitment = CommitmentPlan::prepare_chunked(
            context,
            poseidon,
            leaves,
            arity * 2,
            cap_height,
            EvaluationOrder::Natural,
            max_chunk_rows,
        )?;
        let chunk_rows = commitment.chunk_rows();
        let packing_params = (0..leaves)
            .step_by(chunk_rows)
            .map(|offset| {
                context.prepare_params([
                    evaluations as u32,
                    arity as u32,
                    chunk_rows as u32,
                    offset as u32,
                ])
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            kernels,
            evaluations,
            commitment,
            packing_params,
        })
    }

    pub fn workspace_field_counts(&self) -> [usize; 3] {
        self.commitment.workspace_field_counts()
    }

    pub fn cap(&self, tree: &DeviceFieldSlice) -> Result<DeviceFieldSlice> {
        self.commitment.cap(tree)
    }

    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        evaluations: &DeviceFieldSlice,
        input_chunk: &DeviceFieldSlice,
        leaf_chunk: &DeviceFieldSlice,
        tree: &DeviceFieldSlice,
    ) -> Result<()> {
        ensure!(
            evaluations.len() == self.evaluations * 2,
            "FRI evaluation buffer shape mismatch"
        );
        let chunk_rows = self.commitment.chunk_rows();
        self.commitment.encode_with_packing(
            encoder,
            input_chunk,
            leaf_chunk,
            tree,
            |encoder, offset| {
                let group = encoder.bind_with_params(
                    &self.kernels.pack,
                    &[
                        FieldBinding::ReadWrite(input_chunk),
                        FieldBinding::Read(evaluations.into()),
                    ],
                    Some(&self.packing_params[offset / chunk_rows]),
                    "FRI leaf packing",
                )?;
                encoder.dispatch_elements(
                    &self.kernels.pack,
                    &group,
                    input_chunk.len(),
                    "FRI leaf packing",
                )
            },
        )
    }
}

#[cfg(test)]
mod tests;
