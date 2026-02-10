pub mod aggregator;
pub mod circuits;
pub mod dummy_proof;
mod util;

pub use aggregator::WormholeProofAggregator;
pub use circuits::tree::{AggregatedProof, TreeAggregationConfig};
