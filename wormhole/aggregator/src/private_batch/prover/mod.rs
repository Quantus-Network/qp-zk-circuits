//! Private-batch aggregation prover.
//!
//! # Admission boundary
//!
//! [`PrivateBatchProver::commit`] is the untrusted-input boundary: it
//! cryptographically verifies each leaf proof against the pinned leaf
//! verifier, enforces batch metadata compatibility, rejects empty and
//! all-dummy batches, and pads with the validated dummy template — all
//! before the expensive recursive proving run. The low-level witness filler
//! (`witness::fill_private_batch_witness`) performs only structural
//! proof-shape checks and target assignment, assuming those invariants
//! already hold, so it must not be reachable from outside the crate
//! (audit finding: the exported helper let downstream services feed
//! invalid, incompatible, or all-dummy proof vectors straight into the
//! proving path, bypassing commit; mirrors the public-batch prover's
//! `pub(crate)` stance):
//!
//! ```compile_fail
//! use qp_wormhole_aggregator::private_batch::prover::witness::fill_private_batch_witness;
//! ```
//!
//! A `compile_fail` test passes on ANY compile error, so on its own it
//! would keep passing — for the wrong reason — if the crate or module were
//! renamed. The passing companion below pins the same fully qualified path
//! prefix, so only the `witness` segment's privacy can be what fails above:
//!
//! ```
//! use qp_wormhole_aggregator::private_batch::prover::PrivateBatchProver;
//! ```

pub mod lib;
/// Low-level witness filler — not an untrusted-input boundary.
///
/// Cryptographic verification, metadata compatibility, dummy-padding, and the
/// non-all-dummy admission check live in [`PrivateBatchProver::commit`]. This
/// module is `pub(crate)` so downstream services cannot bypass those checks by
/// calling [`witness::fill_private_batch_witness`] directly (see the module
/// docs above and the public-batch analogue).
pub(crate) mod witness;

pub(crate) use lib::verify_dummy_leaf_template;
pub(crate) use witness::fill_private_batch_witness;
pub use lib::PrivateBatchProver;
