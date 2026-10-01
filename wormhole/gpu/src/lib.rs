//! GPU execution support for Wormhole proving.
//!
//! Enable `wgpu` to use the Metal/Vulkan execution backend. This crate currently
//! supplies execution resources and prepared mathematical operations, not a
//! selectable public-batch proving backend. Prepare kernels, FFT tables, and
//! operation plans once, then encode arithmetic, FFTs, commitments, and quotient
//! evaluation over resident canonical Goldilocks buffers. Encoding does not
//! compile shaders, wait for the GPU, or export intermediate results.
//!
//! `constraint-export` additionally enables quotient evaluation. It requires
//! the dependency's backend-neutral constraint exporter; until that is published,
//! validation requires a local Cargo override, not a production dependency pin.
//!
//! Hardware-independent checks:
//! `cargo test --release -p qp-wormhole-gpu --features constraint-export`.
//! Hardware execution check (Metal on macOS, Vulkan elsewhere):
//! `cargo test --release -p qp-wormhole-gpu --features constraint-export --lib -- --ignored`.
//! These are small execution and CPU-parity checks, not proof benchmarks.

#[cfg(feature = "wgpu")]
mod runtime;

#[cfg(feature = "wgpu")]
mod operations;

#[cfg(feature = "wgpu")]
pub use operations::{
    ArithmeticKernels, ArithmeticPlan, CommitmentPlan, EvaluationOrder, FftKernels, FftPlan,
    FieldOperation, PoseidonKernels,
};

#[cfg(feature = "constraint-export")]
pub use operations::{QuotientLayout, QuotientPlan};

#[cfg(feature = "wgpu")]
pub use runtime::{
    DeviceContext, DeviceFieldSlice, FieldSource, FixedFieldSlice, PendingSubmission, ProofEncoder,
    ProofWorkspace,
};
