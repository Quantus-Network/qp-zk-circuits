#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod circuit;
pub mod inputs;

pub use crate::inputs::{CircuitInputs, ParsePublicInputs, PrivateCircuitInputs};
pub use qp_ownership_inputs::{
    BytesDigest, PublicCircuitInputs, CLAIM_ACCOUNT_END_INDEX, CLAIM_ACCOUNT_START_INDEX,
    MIN_OWNERSHIP_SECURITY_BITS, PUBLIC_INPUTS_FELTS_LEN, WORMHOLE_ADDRESS_END_INDEX,
    WORMHOLE_ADDRESS_START_INDEX,
};
pub use wormhole_circuit::sensitive::Secret;
