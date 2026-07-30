pub mod lib;
pub mod witness;

pub(crate) use lib::verify_dummy_leaf_template;
pub use lib::PrivateBatchProver;
pub use witness::fill_private_batch_witness;
