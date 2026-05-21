pub mod inner;
pub mod lib;
pub mod ordering;
pub mod outer;
pub mod session;
pub mod witness;

pub use lib::Layer0AggregationProver as LegacyLayer0AggregationProver;
pub use session::{
    InnerExecutionMode, Layer0AggregateOutput, Layer0AggregationArtifacts, Layer0AggregationProver,
    Layer0AggregationVerifierArtifacts, Layer0Verifier,
};
pub use witness::fill_layer0_aggregation_witness;
