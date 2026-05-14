//! Proof aggregation types.
//!
//! This module provides:
//!
//! - [`AggregatedProof`]: A proof bundled with its circuit data.
//!
//! For building recursive verification circuits, use [`crate::recursive::add_recursive_verifiers`]
//! which safely bakes the expected verifier key as constants (preventing verifier key substitution
//! attacks).

use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};

use crate::circuit::{C, D, F};

/// A proof bundled with the circuit data needed to verify and extend it.
#[derive(Debug)]
pub struct AggregatedProof {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
}
