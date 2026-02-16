pub mod aggregator;
pub mod circuits;
pub mod config;
pub mod dummy_proof;

pub use aggregator::WormholeProofAggregator;
pub use circuits::tree::WormholeAggregationWrapper;
pub use config::CircuitBinsConfig;
pub use dummy_proof::{
    build_dummy_circuit_inputs, generate_dummy_proof, DUMMY_BLOCK_HASH, DUMMY_EXIT_ACCOUNT,
};
