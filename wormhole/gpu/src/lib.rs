//! GPU execution support for Wormhole proving.
//!
//! Enable `wgpu` to use the Metal/Vulkan execution backend. This crate currently
//! supplies execution resources, prepared mathematical operations, and resident
//! wire, permutation-product, quotient, opening and FRI-input stages, not a
//! selectable public-batch proving backend. PreparedCircuit retains the circuit's fixed oracle, FFT tables,
//! wire-gather map, and pipelines across proof workspaces. CPU witness generators
//! run before upload; gathering, FFTs, products, quotient evaluation and Merkle
//! commitments, openings and FRI-input preparation run on GPU. The coordinator
//! supplies transcript challenges and explicitly exports the small opening set.
//! Encoding does not compile shaders, wait for the GPU, or export intermediate
//! results.
//!
//! `constraint-export` additionally enables quotient and opening stages. It requires
//! the dependency's backend-neutral constraint exporter; until that is published,
//! validation requires a local Cargo override, not a production dependency pin.
//!
//! Hardware-independent checks:
//! `cargo test --release -p qp-wormhole-gpu --features constraint-export`.
//! Hardware execution check (Metal on macOS, Vulkan elsewhere):
//! `cargo test --release -p qp-wormhole-gpu --features constraint-export --lib -- --ignored`.
//! These are small execution and CPU-parity checks, not proof benchmarks.
//! `prepare_public_batch` measures initialization with the actual public-batch
//! circuit, including specialized quotient pipelines; it generates no proof.

#[cfg(feature = "wgpu")]
mod runtime;

#[cfg(feature = "wgpu")]
mod operations;

#[cfg(feature = "wgpu")]
mod circuit;

#[cfg(feature = "wgpu")]
pub use circuit::{
    CircuitPreparationTimings, FixedCommitment, PermutationBuffers, PermutationCommitment,
    PolynomialCommitment, PreparationOptions, PreparedCircuit, WireBuffers, WireCommitment,
};

#[cfg(feature = "constraint-export")]
pub use circuit::{
    FriInput, OpeningBuffers, QuotientBuffers, QuotientCommitment, ResidentOpeningSet,
};

#[cfg(feature = "wgpu")]
pub use operations::{
    ArithmeticKernels, ArithmeticPlan, CommitmentPlan, EvaluationOrder, ExtensionKernels,
    FftKernels, FftPlan, FieldOperation, LinearDivisionPlan, PolynomialCombinationPlan,
    PolynomialEvaluationPlan, PoseidonKernels, PrefixProductPlan,
};

#[cfg(feature = "constraint-export")]
pub use operations::{QuotientLayout, QuotientPlan};

#[cfg(feature = "wgpu")]
pub use runtime::{
    DeviceContext, DeviceFieldSlice, FieldSource, FixedFieldSlice, PendingSubmission, ProofEncoder,
    ProofWorkspace,
};
