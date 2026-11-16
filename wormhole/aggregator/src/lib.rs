pub mod aggregator;
pub mod common;
pub mod config;
pub mod dummy_proof;
pub mod pool;
pub mod private_batch;
pub mod public_batch;

#[cfg(feature = "profile")]
pub mod profile;

pub use config::{validate_proof_count, CircuitBinsConfig, MAX_PROOF_COUNT};
pub use dummy_proof::{
    build_dummy_circuit_inputs, generate_dummy_proof, DUMMY_BLOCK_HASH, DUMMY_EXIT_ACCOUNT,
};

/// Batch sizes of the circuits embedded in the deployed runtime (chain `v1.0.2-Qm`, spec 153).
pub mod deployed {
    pub const NUM_LEAF_PROOFS: usize = 7;
    pub const NUM_PRIVATE_BATCH_PROOFS: usize = 53;
}
