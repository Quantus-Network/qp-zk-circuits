pub mod lib;
/// Low-level witness filler — not an untrusted-input boundary.
///
/// Cryptographic verification, metadata compatibility, dummy-padding, and the
/// non-all-dummy admission check live in [`PublicBatchProver::commit`]. This
/// module is `pub(crate)` so downstream services cannot bypass those checks by
/// calling [`witness::fill_public_batch_witness`] directly (audit finding:
/// exposed helper deferred rejection until the expensive proving path / let
/// all-dummy batches occupy a proving window).
pub(crate) mod witness;

pub(crate) use lib::{preflight_private_batch_proofs, verify_dummy_private_batch_template};
pub use lib::{PublicBatchInputs, PublicBatchProver};
