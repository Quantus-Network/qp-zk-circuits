#![cfg_attr(not(feature = "std"), no_std)]
// This crate handles the raw spend secret; keep memory handling auditable by
// construction. Scrubbing that needs volatile writes goes through the vetted
// `zeroize` dependency instead of local `unsafe` (see `sensitive`).
#![forbid(unsafe_code)]

extern crate alloc;

pub mod block_header;
pub mod circuit;
pub mod inputs;
pub mod nullifier;
#[cfg(feature = "profile")]
pub mod profile;
pub mod sensitive;
pub mod substrate_account;
pub mod unspendable_account;
pub mod zk_merkle_proof; // 4-ary Poseidon Merkle proof

// Re-export codec traits from common for convenience
pub use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
