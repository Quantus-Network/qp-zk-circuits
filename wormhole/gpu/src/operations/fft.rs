use super::{read, table_size, write, FIELD};
use crate::runtime::{
    DeviceContext, DeviceFieldSlice, FieldBinding, FieldSource, FixedFieldSlice, KernelParams,
    PreparedKernel, ProofEncoder,
};
use anyhow::{ensure, Result};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;
use std::sync::Arc;

/// Reusable pipelines for all supported FFT sizes; prepare once per device.
pub struct FftKernels {
    prepare: PreparedKernel,
    butterfly: PreparedKernel,
    normalize: PreparedKernel,
}

impl FftKernels {
    pub fn prepare(context: &DeviceContext) -> Result<Self> {
        let source = format!("{FIELD}\n{}", include_str!("../shaders/fft.wgsl"));
        let specs = [write(1), read(1), read(1), read(1)];
        Ok(Self {
            prepare: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "FFT preparation",
                "prepare",
                true,
            )?,
            butterfly: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "FFT butterfly",
                "butterfly",
                true,
            )?,
            normalize: PreparedKernel::prepare_entry(
                context,
                &source,
                &specs,
                "IFFT normalization",
                "normalize",
                true,
            )?,
        })
    }
}

/// Natural-order forward coset FFT or inverse coset FFT over one or more
/// column-major polynomials of the same size. Separate input and output
/// allocations are required. Zero-padded forward inputs skip the known trivial
/// butterfly rounds, as in the CPU implementation. A batch must fit one storage
/// binding; the caller can encode several batches with the same prepared plan.
pub struct FftPlan {
    kernels: Arc<FftKernels>,
    degree: usize,
    rows: usize,
    roots: FixedFieldSlice,
    input_factors: FixedFieldSlice,
    output_factors: Option<FixedFieldSlice>,
    preparation: KernelParams,
    stages: Vec<KernelParams>,
}

impl FftPlan {
    pub fn prepare_coset(
        context: &DeviceContext,
        kernels: Arc<FftKernels>,
        degree: usize,
        rows: usize,
        shift: F,
    ) -> Result<Self> {
        Self::prepare(context, kernels, degree, rows, shift, false)
    }

    pub fn prepare_inverse(
        context: &DeviceContext,
        kernels: Arc<FftKernels>,
        rows: usize,
        shift: F,
    ) -> Result<Self> {
        Self::prepare(context, kernels, rows, rows, shift, true)
    }

    fn prepare(
        context: &DeviceContext,
        kernels: Arc<FftKernels>,
        degree: usize,
        rows: usize,
        shift: F,
        inverse: bool,
    ) -> Result<Self> {
        table_size(rows, 1)?;
        ensure!(
            degree.is_power_of_two()
                && rows.is_power_of_two()
                && degree <= rows
                && rows.ilog2() <= 32,
            "invalid FFT shape"
        );
        ensure!(shift != F::ZERO, "FFT coset shift is zero");
        let limits = context.limits();
        ensure!(
            (rows as u64) * 8 <= limits.max_buffer_size
                && (rows as u64) * 8 <= u64::from(limits.max_storage_buffer_binding_size),
            "FFT table exceeds device buffer limits"
        );
        let root = F::primitive_root_of_unity(rows.ilog2() as usize);
        let root = if inverse { root.inverse() } else { root };
        let roots =
            context.prepare_fixed(&root.powers().take((rows / 2).max(1)).collect::<Vec<_>>())?;
        let input_factors = context.prepare_fixed(&if inverse {
            vec![F::ONE; degree]
        } else {
            shift.powers().take(degree).collect()
        })?;
        let output_factors = if inverse {
            let scale = F::from_canonical_usize(rows).inverse();
            Some(
                context.prepare_fixed(
                    &shift
                        .inverse()
                        .powers()
                        .take(rows)
                        .map(|power| scale * power)
                        .collect::<Vec<_>>(),
                )?,
            )
        } else {
            None
        };
        let padding = rows.ilog2() - degree.ilog2();
        let preparation =
            context.prepare_params([rows as u32, degree as u32, rows.ilog2(), padding])?;
        let stages = (padding + 1..=rows.ilog2())
            .map(|stage| {
                context.prepare_params([rows as u32, degree as u32, rows.ilog2(), 1 << (stage - 1)])
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            kernels,
            degree,
            rows,
            roots,
            input_factors,
            output_factors,
            preparation,
            stages,
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
            !input.is_empty()
                && input.len().is_multiple_of(self.degree)
                && table_size(self.rows, input.len() / self.degree)? == output.len(),
            "FFT buffer shape mismatch"
        );
        let bindings = [
            FieldBinding::ReadWrite(output),
            FieldBinding::Read(input),
            FieldBinding::Read((&self.roots).into()),
            FieldBinding::Read((&self.input_factors).into()),
        ];
        let group = encoder.bind_with_params(
            &self.kernels.prepare,
            &bindings,
            Some(&self.preparation),
            "FFT preparation",
        )?;
        encoder.dispatch_elements(
            &self.kernels.prepare,
            &group,
            output.len(),
            "FFT preparation",
        )?;
        for params in &self.stages {
            let group = encoder.bind_with_params(
                &self.kernels.butterfly,
                &bindings,
                Some(params),
                "FFT butterfly",
            )?;
            encoder.dispatch_elements(
                &self.kernels.butterfly,
                &group,
                output.len() / 2,
                "FFT butterfly",
            )?;
        }
        if let Some(factors) = &self.output_factors {
            let bindings = [
                FieldBinding::ReadWrite(output),
                FieldBinding::Read(input),
                FieldBinding::Read((&self.roots).into()),
                FieldBinding::Read(factors.into()),
            ];
            let group = encoder.bind_with_params(
                &self.kernels.normalize,
                &bindings,
                Some(&self.preparation),
                "IFFT normalization",
            )?;
            encoder.dispatch_elements(
                &self.kernels.normalize,
                &group,
                output.len(),
                "IFFT normalization",
            )?;
        }
        Ok(())
    }
}
