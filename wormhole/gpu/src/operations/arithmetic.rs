use super::{read, table_size, write, FIELD};
use crate::runtime::{
    DeviceContext, DeviceFieldSlice, FieldBinding, FieldSource, KernelParams, PreparedKernel,
    ProofEncoder,
};
use anyhow::{ensure, Result};
use std::sync::Arc;

/// Element-wise canonical Goldilocks operations.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum FieldOperation {
    Add,
    Subtract,
    Multiply,
    Square,
    Sbox,
}

impl FieldOperation {
    pub(super) fn input_columns(self) -> usize {
        match self {
            Self::Square | Self::Sbox => 1,
            _ => 2,
        }
    }
}

/// One reusable arithmetic pipeline per device.
pub struct ArithmeticKernels {
    kernel: PreparedKernel,
}

impl ArithmeticKernels {
    pub fn prepare(context: &DeviceContext) -> Result<Self> {
        let source = format!("{FIELD}\n{}", include_str!("../shaders/arithmetic.wgsl"));
        Ok(Self {
            kernel: PreparedKernel::prepare_entry(
                context,
                &source,
                &[write(1), read(1)],
                "Goldilocks arithmetic",
                "main",
                true,
            )?,
        })
    }
}

/// Two column-major inputs for binary operations, one for unary operations;
/// one output column. Pipelines and parameters are prepared before encoding.
pub struct ArithmeticPlan {
    kernels: Arc<ArithmeticKernels>,
    params: KernelParams,
    rows: usize,
    operation: FieldOperation,
}

impl ArithmeticPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<ArithmeticKernels>,
        rows: usize,
        operation: FieldOperation,
    ) -> Result<Self> {
        table_size(rows, operation.input_columns())?;
        Ok(Self {
            kernels,
            params: context.prepare_params([rows as u32, operation as u32, 0, 0])?,
            rows,
            operation,
        })
    }

    pub fn encode<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        input: impl Into<FieldSource<'a>>,
        output: &DeviceFieldSlice,
    ) -> Result<()> {
        let input = input.into();
        ensure!(
            input.len() == self.rows * self.operation.input_columns() && output.len() == self.rows,
            "arithmetic buffer shape mismatch"
        );
        let bindings = encoder.bind_with_params(
            &self.kernels.kernel,
            &[FieldBinding::ReadWrite(output), FieldBinding::Read(input)],
            Some(&self.params),
            "Goldilocks arithmetic",
        )?;
        encoder.dispatch_elements(
            &self.kernels.kernel,
            &bindings,
            self.rows,
            "Goldilocks arithmetic",
        )
    }
}
