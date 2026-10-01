//! GPU execution support for Wormhole proving.
//!
//! Enable `wgpu` to use the Metal/Vulkan execution backend. This crate currently
//! supplies execution resources, not a selectable public-batch proving backend.
//! Circuit preparation will create pipelines and reusable workspaces; host
//! protocol code will encode operations over resident field-value buffers.
//!
//! Hardware-independent checks:
//! `cargo test --release -p qp-wormhole-gpu --features wgpu`.
//! Hardware execution check (Metal on macOS, Vulkan elsewhere):
//! `cargo test --release -p qp-wormhole-gpu --features wgpu --lib -- --ignored`.
//! This check runs a tiny execution oracle, not a proof benchmark.

#[cfg(feature = "wgpu")]
mod runtime;

#[cfg(feature = "wgpu")]
pub use runtime::{
    DeviceContext, DeviceFieldSlice, FieldSource, FixedFieldSlice, PendingSubmission, ProofEncoder,
    ProofWorkspace,
};
