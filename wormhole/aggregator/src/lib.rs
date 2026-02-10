pub mod aggregator;
pub mod circuits;
pub mod dummy_proof;
mod util;

pub use aggregator::WormholeProofAggregator;
pub use circuits::tree::{AggregatedProof, TreeAggregationConfig};
pub use dummy_proof::{generate_dummy_proof, DUMMY_BLOCK_HASH, DUMMY_EXIT_ACCOUNT};
