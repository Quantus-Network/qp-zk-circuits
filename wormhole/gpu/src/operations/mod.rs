//! Prepared mathematical operations over resident canonical Goldilocks buffers.
//! Plans own immutable tables and dispatch parameters. Encoding never compiles
//! pipelines, waits for the GPU, or reads intermediate results back to the host.

mod arithmetic;
mod commitment;
mod fft;
#[cfg(feature = "constraint-export")]
mod quotient;
mod scan;

pub use arithmetic::{ArithmeticKernels, ArithmeticPlan, FieldOperation};
pub use commitment::{CommitmentPlan, EvaluationOrder, PoseidonKernels};
pub use fft::{FftKernels, FftPlan};
#[cfg(feature = "constraint-export")]
pub use quotient::{QuotientLayout, QuotientPlan};
pub use scan::PrefixProductPlan;

use crate::runtime::{BindingAccess, FieldBindingSpec};
use anyhow::{ensure, Result};

pub(crate) const FIELD: &str = include_str!("../shaders/field.wgsl");

pub(crate) fn read(min_elements: usize) -> FieldBindingSpec {
    FieldBindingSpec {
        access: BindingAccess::Read,
        min_elements,
    }
}

pub(crate) fn write(min_elements: usize) -> FieldBindingSpec {
    FieldBindingSpec {
        access: BindingAccess::ReadWrite,
        min_elements,
    }
}

fn table_size(rows: usize, columns: usize) -> Result<usize> {
    let size = rows.checked_mul(columns);
    ensure!(
        rows > 0 && columns > 0 && size.is_some_and(|n| n <= u32::MAX as usize),
        "table exceeds u32 GPU addressing"
    );
    Ok(size.unwrap())
}

#[cfg(test)]
mod tests;
