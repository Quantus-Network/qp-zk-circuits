//! ZK Wrapper circuit for phone-side aggregation.
//!
//! This module provides a simple ZK wrapper circuit that:
//! 1. Verifies a non-ZK aggregated proof
//! 2. Forwards all public inputs unchanged
//!
//! This allows a 2-step proving process:
//! 1. Non-ZK L0 aggregation (fast, ~3.7s for 16 proofs)
//! 2. ZK wrapper (small, ~1s to add ZK property)
//!
//! Total: ~4.8s vs ~8.8s for direct ZK L0 aggregation (~1.8x speedup)
//!
//! Note: The actual prover implementation lives in `layer0::prover::wrapper`
//! as `Layer0WrapperProver`, which combines non-ZK L0 aggregation with ZK wrapping
//! in a single convenient API.

pub mod build;
pub mod circuit;

pub use circuit::ZkWrapperCircuit;
