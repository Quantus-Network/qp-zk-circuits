use super::{read, table_size, write, FIELD};
use crate::runtime::{FieldBinding, KernelParams, PreparedKernel};
use crate::{DeviceContext, DeviceFieldSlice, FieldSource, ProofEncoder};
use anyhow::{ensure, Result};
use std::sync::Arc;

pub(crate) const EXTENSION: &str = include_str!("../shaders/extension.wgsl");

/// Quadratic Goldilocks polynomial pipelines, shared across circuit stages.
pub struct ExtensionKernels {
    evaluate: PreparedKernel,
    reduce: PreparedKernel,
    combine: PreparedKernel,
    scan_coefficients: PreparedKernel,
    scan_totals: PreparedKernel,
    carry: PreparedKernel,
    finish: PreparedKernel,
}

impl ExtensionKernels {
    pub fn prepare(context: &DeviceContext) -> Result<Self> {
        let evaluation = format!(
            "{FIELD}\n{EXTENSION}\n{}",
            include_str!("../shaders/polynomial_evaluation.wgsl")
        );
        let division = format!(
            "{FIELD}\n{EXTENSION}\n{}",
            include_str!("../shaders/linear_division.wgsl")
        );
        let prepare = |source: &str, specs: &[crate::runtime::FieldBindingSpec], entry| {
            PreparedKernel::prepare_entry(context, source, specs, entry, entry, true)
        };
        Ok(Self {
            evaluate: prepare(&evaluation, &[write(2), read(1), read(2)], "evaluate")?,
            reduce: prepare(&evaluation, &[write(2), read(2), read(2)], "reduce")?,
            combine: prepare(
                &format!(
                    "{FIELD}\n{EXTENSION}\n{}",
                    include_str!("../shaders/polynomial_combination.wgsl")
                ),
                &[write(2), read(1), read(2)],
                "main",
            )?,
            scan_coefficients: prepare(
                &division,
                &[write(2), read(2), write(2), read(2)],
                "scan_coefficients",
            )?,
            scan_totals: prepare(
                &division,
                &[write(2), read(2), write(2), read(2)],
                "scan_totals",
            )?,
            carry: prepare(&division, &[write(2), read(2), write(2), read(2)], "carry")?,
            finish: prepare(&division, &[write(2), read(2), write(2), read(2)], "finish")?,
        })
    }
}

/// Evaluate a column-major base-field coefficient batch at one extension point.
/// Results and reduction scratch use interleaved (real, extension) pairs.
/// Workgroups evaluate bounded Horner chunks and recursively sum partials.
pub struct PolynomialEvaluationPlan {
    kernels: Arc<ExtensionKernels>,
    degree: usize,
    columns: usize,
    point: usize,
    blocks: usize,
    params: KernelParams,
    reductions: Vec<(usize, KernelParams)>,
    scratch: Vec<usize>,
}

impl PolynomialEvaluationPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<ExtensionKernels>,
        degree: usize,
        columns: usize,
        point: usize,
    ) -> Result<Self> {
        table_size(degree, columns)?;
        table_size(columns, 2)?;
        let blocks = degree.div_ceil(4096);
        let limit = context.limits().max_compute_workgroups_per_dimension as usize;
        ensure!(
            blocks <= limit && columns <= limit && point < u32::MAX as usize,
            "polynomial evaluation exceeds dispatch limits"
        );
        let params =
            context.prepare_params([degree as u32, blocks as u32, columns as u32, point as u32])?;
        let mut scratch = Vec::new();
        if blocks > 1 {
            scratch.push(table_size(blocks, columns * 2)?);
        }
        let mut rows = blocks;
        let mut reductions = Vec::new();
        while rows > 1 {
            let next = rows.div_ceil(64);
            reductions.push((
                next,
                context.prepare_params([rows as u32, next as u32, columns as u32, point as u32])?,
            ));
            if next > 1 {
                scratch.push(table_size(next, columns * 2)?);
            }
            rows = next;
        }
        Ok(Self {
            kernels,
            degree,
            columns,
            point,
            blocks,
            params,
            reductions,
            scratch,
        })
    }

    pub fn workspace_field_counts(&self) -> &[usize] {
        &self.scratch
    }

    /// Extra input columns may be present; only the prepared prefix is evaluated.
    /// Points are interleaved extension pairs. Scratch views may exceed the plan's
    /// minimum sizes so different column batches can reuse the same allocations.
    pub fn encode<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        coefficients: impl Into<FieldSource<'a>>,
        points: &DeviceFieldSlice,
        output: &DeviceFieldSlice,
        scratch: &[DeviceFieldSlice],
    ) -> Result<()> {
        let coefficients = coefficients.into();
        ensure!(
            coefficients.len() >= self.degree * self.columns
                && points.len() / 2 > self.point
                && output.len() == self.columns * 2
                && scratch.len() == self.scratch.len()
                && scratch
                    .iter()
                    .zip(&self.scratch)
                    .all(|(buffer, &size)| buffer.len() >= size),
            "polynomial evaluation buffer shape mismatch"
        );
        let destination = if self.blocks == 1 {
            output
        } else {
            &scratch[0]
        };
        let group = encoder.bind_with_params(
            &self.kernels.evaluate,
            &[
                FieldBinding::ReadWrite(destination),
                FieldBinding::Read(coefficients),
                FieldBinding::Read(points.into()),
            ],
            Some(&self.params),
            "polynomial evaluation",
        )?;
        encoder.dispatch(
            &self.kernels.evaluate,
            &group,
            [self.blocks as u32, self.columns as u32, 1],
            "polynomial evaluation",
        )?;
        for (index, (blocks, params)) in self.reductions.iter().enumerate() {
            let destination = if *blocks == 1 {
                output
            } else {
                &scratch[index + 1]
            };
            let group = encoder.bind_with_params(
                &self.kernels.reduce,
                &[
                    FieldBinding::ReadWrite(destination),
                    FieldBinding::Read((&scratch[index]).into()),
                    FieldBinding::Read(points.into()),
                ],
                Some(params),
                "polynomial evaluation reduction",
            )?;
            encoder.dispatch(
                &self.kernels.reduce,
                &group,
                [*blocks as u32, self.columns as u32, 1],
                "polynomial evaluation reduction",
            )?;
        }
        Ok(())
    }
}

/// Combine one base-field polynomial batch using extension weights. Output has
/// two component-major degree-length planes, suitable for the base-field FFT.
pub struct PolynomialCombinationPlan {
    kernels: Arc<ExtensionKernels>,
    degree: usize,
    columns: usize,
    weight_end: usize,
    params: KernelParams,
}

impl PolynomialCombinationPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<ExtensionKernels>,
        degree: usize,
        columns: usize,
        first_weight: usize,
        accumulate: bool,
    ) -> Result<Self> {
        table_size(degree, columns)?;
        table_size(degree, 2)?;
        let weight_end = first_weight
            .checked_add(columns)
            .filter(|&n| n <= u32::MAX as usize)
            .ok_or_else(|| anyhow::anyhow!("polynomial combination weight overflow"))?;
        Ok(Self {
            kernels,
            degree,
            columns,
            weight_end,
            params: context.prepare_params([
                degree as u32,
                columns as u32,
                first_weight as u32,
                u32::from(accumulate),
            ])?,
        })
    }

    pub fn encode<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        coefficients: impl Into<FieldSource<'a>>,
        weights: &DeviceFieldSlice,
        output: &DeviceFieldSlice,
    ) -> Result<()> {
        let coefficients = coefficients.into();
        ensure!(
            coefficients.len() >= self.degree * self.columns
                && weights.len() / 2 >= self.weight_end
                && output.len() == self.degree * 2,
            "polynomial combination buffer shape mismatch"
        );
        let group = encoder.bind_with_params(
            &self.kernels.combine,
            &[
                FieldBinding::ReadWrite(output),
                FieldBinding::Read(coefficients),
                FieldBinding::Read(weights.into()),
            ],
            Some(&self.params),
            "opening polynomial combination",
        )?;
        encoder.dispatch_elements(
            &self.kernels.combine,
            &group,
            self.degree,
            "opening polynomial combination",
        )
    }
}

/// Divide an extension polynomial by (X - point), discarding the remainder as
/// PolynomialCoeffs::divide_by_linear does. Inclusive Horner scans run within
/// workgroups and recursively across block totals, rather than one full-trace
/// sequential loop or logarithmically many full-buffer passes. Output is padded
/// with one zero coefficient and uses two component-major planes.
pub struct LinearDivisionPlan {
    kernels: Arc<ExtensionKernels>,
    degree: usize,
    point: usize,
    levels: Vec<(usize, KernelParams)>,
    scratch: Vec<usize>,
}

impl LinearDivisionPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<ExtensionKernels>,
        degree: usize,
        point: usize,
    ) -> Result<Self> {
        table_size(degree, 2)?;
        ensure!(
            point < u32::MAX as usize,
            "linear division point index overflow"
        );
        let limit = context.limits().max_compute_workgroups_per_dimension as usize;
        let mut rows = degree;
        let mut power = 1u32;
        let mut levels = Vec::new();
        let mut scratch = Vec::new();
        loop {
            let blocks = rows.div_ceil(256);
            ensure!(blocks <= limit, "linear division exceeds dispatch limits");
            levels.push((
                blocks,
                context.prepare_params([rows as u32, blocks as u32, power, point as u32])?,
            ));
            scratch.extend([rows * 2, blocks * 2]);
            if blocks == 1 {
                break;
            }
            rows = blocks;
            power = power
                .checked_mul(256)
                .ok_or_else(|| anyhow::anyhow!("linear division exponent overflow"))?;
        }
        Ok(Self {
            kernels,
            degree,
            point,
            levels,
            scratch,
        })
    }

    pub fn workspace_field_counts(&self) -> &[usize] {
        &self.scratch
    }

    /// Input and output may alias: all input reads precede the final placement
    /// dispatch. Scratch allocations must be distinct from input and output.
    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        input: &DeviceFieldSlice,
        points: &DeviceFieldSlice,
        output: &DeviceFieldSlice,
        scratch: &[DeviceFieldSlice],
    ) -> Result<()> {
        ensure!(
            input.len() == self.degree * 2
                && output.len() == input.len()
                && points.len() / 2 > self.point
                && scratch.len() == self.scratch.len()
                && scratch
                    .iter()
                    .zip(&self.scratch)
                    .all(|(buffer, &size)| buffer.len() == size),
            "linear division buffer shape mismatch"
        );
        for (level, (blocks, params)) in self.levels.iter().enumerate() {
            let kernel = if level == 0 {
                &self.kernels.scan_coefficients
            } else {
                &self.kernels.scan_totals
            };
            let source = if level == 0 {
                input
            } else {
                &scratch[2 * level - 1]
            };
            let bindings = encoder.bind_with_params(
                kernel,
                &[
                    FieldBinding::ReadWrite(&scratch[2 * level]),
                    FieldBinding::Read(source.into()),
                    FieldBinding::ReadWrite(&scratch[2 * level + 1]),
                    FieldBinding::Read(points.into()),
                ],
                Some(params),
                "linear division block scan",
            )?;
            encoder.dispatch(
                kernel,
                &bindings,
                [*blocks as u32, 1, 1],
                "linear division block scan",
            )?;
        }
        for level in (0..self.levels.len() - 1).rev() {
            let params = &self.levels[level].1;
            let bindings = encoder.bind_with_params(
                &self.kernels.carry,
                &[
                    FieldBinding::ReadWrite(&scratch[2 * level]),
                    FieldBinding::Read((&scratch[2 * level + 2]).into()),
                    FieldBinding::ReadWrite(&scratch[2 * level + 1]),
                    FieldBinding::Read(points.into()),
                ],
                Some(params),
                "linear division block carry",
            )?;
            encoder.dispatch_elements(
                &self.kernels.carry,
                &bindings,
                self.scratch[2 * level] / 2,
                "linear division block carry",
            )?;
        }
        let bindings = encoder.bind_with_params(
            &self.kernels.finish,
            &[
                FieldBinding::ReadWrite(output),
                FieldBinding::Read((&scratch[0]).into()),
                FieldBinding::ReadWrite(&scratch[1]),
                FieldBinding::Read(points.into()),
            ],
            Some(&self.levels[0].1),
            "linear division coefficient placement",
        )?;
        encoder.dispatch_elements(
            &self.kernels.finish,
            &bindings,
            self.degree,
            "linear division coefficient placement",
        )
    }
}

#[cfg(test)]
mod tests;
