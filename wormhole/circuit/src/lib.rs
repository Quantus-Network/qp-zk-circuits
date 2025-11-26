#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block_header;
pub mod circuit;
pub mod inputs;
pub mod nullifier;
pub mod storage_proof;
pub mod substrate_account;
pub mod unspendable_account;

// Re-export codec traits from common for convenience
pub use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
