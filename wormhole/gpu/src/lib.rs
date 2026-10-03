//! GPU execution support for Wormhole proving.
//!
//! Enable `wgpu` to use the Metal/Vulkan execution backend. This crate currently
//! supplies execution resources, prepared mathematical operations, resident
//! proving stages and a blocking proof coordinator. The aggregator's optional
//! `gpu` feature enables backend selection through `PublicBatchProver::with_gpu`
//! or `PublicBatchAggregator::with_gpu`. PreparedCircuit retains the
//! circuit's fixed oracle, FFT tables, wire-gather map, and pipelines across
//! proof workspaces. CPU witness generators run before upload; gathering, FFTs,
//! products, quotient evaluation, Merkle commitments, openings, FRI-input
//! preparation, FRI folding, PoW search and sparse query gathering run on GPU.
//! The coordinator supplies transcript challenges and explicitly exports caps,
//! the small opening set, final polynomial, PoW result and sampled proof data.
//! Encoding does not compile shaders, wait for the GPU, or export intermediate
//! results.
//! PreparedCircuit::prepare_workspace allocates reusable proof buffers;
//! PreparedCircuit::prove runs CPU witness generators and coordinates a proof,
//! while prove_with_partition_witness accepts an already-generated witness.
//!
//! `constraint-export` additionally enables quotient, opening, FRI and proof-tail stages.
//! It requires the dependency's backend-neutral constraint exporter; until that
//! is published, validation requires a local Cargo override, not a production
//! dependency pin.
//!
//! Hardware-independent checks:
//! `cargo test --release -p qp-wormhole-gpu --features constraint-export`.
//! Hardware execution check (Metal on macOS, Vulkan elsewhere):
//! `cargo test --release -p qp-wormhole-gpu --features constraint-export --lib -- --ignored`.
//! These are small execution and CPU-parity checks, not proof benchmarks.
//! The aggregator crate's `prepare_public_batch` example measures initialization
//! with the actual public-batch circuit, including specialized quotient pipelines;
//! it generates no proof.
//!
//! Profiling emits DEBUG spans/events through `tracing`; callers choose a
//! subscriber and output format. Proving signatures are unchanged. Host wall
//! times include overlapping device work and must not be added to GPU times.
//! `DeviceContext::with_options` enables optional compute-pass timestamps.
//! Query sets and resolve/export buffers are retained by each proof workspace;
//! no extra proof submissions are introduced. Capacity is explicit and checked
//! before recording. Pass timings exclude copies and queue/driver gaps; invalid
//! samples have `timestamp_valid = false`, not a fabricated zero duration.
//! Timestamp collection is accounted separately from the queue wait, although
//! instrumented queue waits also include the resolve/copy work. `wait` can
//! cover other work on the device queue, not just this workspace's submission.
//! Resource events report actual encoded upload/copy bytes, readback bytes,
//! dispatches, Metal reservations and PoW trials dispatched (not individual
//! nonces actually evaluated before a successful result). Fixed-field and
//! workspace buffer bytes are planned allocations, not physical peak VRAM;
//! fixed-field bytes exclude pipeline/driver and uniform-parameter allocations.
//! No proof, witness, public-input or challenge values are emitted.
//! The aggregator's `public_batch_compare` example accepts `--profile` for host
//! telemetry and `--timestamps` for GPU pass timings, printing a host table and
//! aggregated kernel/counter JSON independently for initialization and proofs.

#[cfg(feature = "wgpu")]
mod runtime;

#[cfg(feature = "wgpu")]
mod profiling;

#[cfg(feature = "wgpu")]
mod operations;

#[cfg(feature = "wgpu")]
mod circuit;

#[cfg(feature = "wgpu")]
pub use circuit::{
    FixedCommitment, PermutationBuffers, PermutationCommitment, PolynomialCommitment,
    PreparationOptions, PreparedCircuit, WireBuffers, WireCommitment,
};

#[cfg(feature = "constraint-export")]
pub use circuit::{
    FriBuffers, FriCommitment, FriFold, FriInput, FriRoundBuffers, OpeningBuffers,
    ProofTailBuffers, QuotientBuffers, QuotientCommitment, ResidentOpeningSet, ResidentQueryRounds,
};

#[cfg(feature = "wgpu")]
pub use operations::{
    ArithmeticKernels, ArithmeticPlan, CommitmentPlan, EvaluationOrder, ExtensionKernels,
    FftKernels, FftPlan, FieldOperation, FriCommitmentPlan, FriFoldPlan, FriKernels,
    LinearDivisionPlan, MerkleQuery, MerkleQueryKernels, MerkleQueryLayout, MerkleQueryPlan,
    PolynomialCombinationPlan, PolynomialEvaluationPlan, PoseidonKernels, PowKernels, PowPlan,
    PowResult, PrefixProductPlan, ResidentMerkleQueries,
};

#[cfg(feature = "constraint-export")]
pub use operations::{QuotientLayout, QuotientPlan};

#[cfg(feature = "wgpu")]
pub use runtime::{
    DeviceContext, DeviceFieldSlice, DeviceOptions, FieldSource, FixedFieldSlice,
    PendingSubmission, ProofEncoder, ProofWorkspace,
};
