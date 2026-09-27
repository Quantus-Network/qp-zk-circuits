#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod circuit;
pub mod codec;
#[cfg(feature = "formal-export")]
pub mod formal_trace;
pub mod gadget_builder;
pub mod gadgets;
pub mod serialization;
pub mod utils;
pub mod zk_merkle;
