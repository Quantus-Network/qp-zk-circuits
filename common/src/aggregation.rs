//! Generic proof aggregation primitives.
//!
//! This module provides the building blocks for multi-layer proof aggregation:
//!
//! - [`AggregatedProof`]: A proof bundled with its circuit data.
//! - [`AggregationConfig`]: Configuration specifying how many proofs to aggregate.
//! - [`AggregationWrapper`]: Trait for domain-specific wrapper circuits.
//! - [`aggregate_chunk`]: Generic "verify N proofs, concatenate PIs" primitive.
//! - [`aggregate_with_wrapper`]: Combines generic aggregation with a domain wrapper.
//!
//! ## Architecture
//!
//! The aggregation pipeline has two stages:
//!
//! 1. **Generic merge** ([`aggregate_chunk`]): Verifies N proofs from the same circuit and
//!    concatenates their public inputs into a single proof. This is purely mechanical and
//!    layer-agnostic -- it works identically whether merging leaf proofs, aggregated proofs,
//!    or aggregations of aggregations.
//!
//! 2. **Domain wrapper** ([`AggregationWrapper::build_wrapper`]): Transforms the merged proof's
//!    concatenated public inputs into a structured output with domain-specific constraints.
//!    For example, the wormhole wrapper deduplicates exit accounts, validates block consistency,
//!    and replaces dummy nullifiers.
//!
//! ## Multi-Layer Aggregation
//!
//! Higher aggregation layers reuse the same primitives. A layer-1 aggregator would:
//! - Call [`aggregate_chunk`] on N layer-0 aggregated proofs
//! - Apply its own [`AggregationWrapper`] implementation with layer-1-specific constraints

use alloc::vec::Vec;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuit::{C, D, F};

/// A proof bundled with the circuit data needed to verify and extend it.
#[derive(Debug)]
pub struct AggregatedProof {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
}

/// Configuration for flat proof aggregation.
#[derive(Debug, Clone, Copy)]
pub struct AggregationConfig {
    /// Number of inner proofs aggregated into a single proof.
    pub num_leaf_proofs: usize,
}

impl AggregationConfig {
    pub fn new(num_leaf_proofs: usize) -> Self {
        assert!(num_leaf_proofs > 0, "num_leaf_proofs must be > 0");
        Self { num_leaf_proofs }
    }
}

/// Trait for domain-specific wrapper circuits applied after generic aggregation.
///
/// Implementors hold domain-specific state (e.g., dummy nullifiers for wormhole,
/// aggregator addresses for layer-1 fee splitting) and define how to:
///
/// 1. Detect dummy proofs in the inner proof set
/// 2. Build a wrapper circuit that transforms concatenated PIs into structured output
///
/// # Dummy Proof Detection
///
/// Each domain defines its own sentinel for dummy proofs. For example, the wormhole
/// domain uses `block_hash == [0,0,0,0]` as the dummy sentinel. The [`is_dummy`] method
/// allows the orchestration layer to identify dummies for shuffling and padding logic
/// without hardcoding domain-specific knowledge.
pub trait AggregationWrapper {
    /// Returns true if the given proof is a dummy (padding) proof.
    ///
    /// Used by the aggregation orchestrator to:
    /// - Shuffle proofs while keeping a real proof in slot 0 (for valid reference values)
    /// - Potentially apply other pre-aggregation transformations
    fn is_dummy(&self, proof: &ProofWithPublicInputs<F, C, D>) -> bool;

    /// Build a wrapper circuit around the merged proof with domain-specific constraints.
    ///
    /// `merged` is the output of [`aggregate_chunk`] -- a single proof whose public inputs
    /// are the concatenation of all N inner proofs' PIs.
    ///
    /// `n_inner` is the number of inner proofs that were merged.
    ///
    /// Returns a new proof with domain-specific public inputs suitable for on-chain
    /// verification or consumption by a higher aggregation layer.
    fn build_wrapper(
        &self,
        merged: AggregatedProof,
        n_inner: usize,
    ) -> anyhow::Result<AggregatedProof>;
}

/// Generic single-level proof aggregation.
///
/// Verifies N proofs from the same circuit and concatenates their public inputs
/// into a single proof. This is the reusable building block for any aggregation layer.
///
/// All input proofs must share the same [`CommonCircuitData`] and [`VerifierOnlyCircuitData`]
/// (i.e., they must come from the same circuit).
///
/// The output proof's public inputs are the concatenation of all input proofs' PIs:
/// `[proof_0_pi..., proof_1_pi..., ..., proof_N_pi...]`
pub fn aggregate_chunk(
    proofs: &[ProofWithPublicInputs<F, C, D>],
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<AggregatedProof> {
    let mut builder = CircuitBuilder::new(common_data.config.clone());
    let verifier_data_t =
        builder.add_virtual_verifier_data(common_data.fri_params.config.cap_height);

    let mut proof_targets = Vec::with_capacity(proofs.len());
    for _ in 0..proofs.len() {
        let proof_t = builder.add_virtual_proof_with_pis(common_data);
        builder.verify_proof::<C>(&proof_t, &verifier_data_t, common_data);
        builder.register_public_inputs(&proof_t.public_inputs);
        proof_targets.push(proof_t);
    }

    let circuit_data = builder.build();

    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_data_t, verifier_data)?;
    for (target, proof) in proof_targets.iter().zip(proofs) {
        pw.set_proof_with_pis_target(target, proof)?;
    }

    let proof = circuit_data.prove(pw)?;

    Ok(AggregatedProof {
        proof,
        circuit_data,
    })
}

/// Aggregate N proofs with a domain-specific wrapper.
///
/// 1. Merges all proofs via [`aggregate_chunk`] (generic verify + concatenate)
/// 2. Applies the wrapper's domain-specific constraints via [`AggregationWrapper::build_wrapper`]
pub fn aggregate_with_wrapper<W: AggregationWrapper>(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
    wrapper: &W,
) -> anyhow::Result<AggregatedProof> {
    let n = proofs.len();
    let merged = aggregate_chunk(&proofs, common_data, verifier_data)?;
    wrapper.build_wrapper(merged, n)
}

/// Shuffle proofs while ensuring a real proof remains in slot 0 for valid reference values.
///
/// Uses the provided [`AggregationWrapper::is_dummy`] to detect dummy proofs in a
/// domain-agnostic way. This function:
///
/// 1. Finds the first real proof (where `!wrapper.is_dummy(proof)`) and swaps it to slot 0
/// 2. Shuffles all remaining proofs (slots 1..N) with external randomness
///
/// This hides dummy proof positions while maintaining valid circuit semantics
/// (slot 0 must contain a real proof for reference value extraction).
pub fn shuffle_proofs_preserving_first_real<W: AggregationWrapper>(
    proofs: &mut [ProofWithPublicInputs<F, C, D>],
    wrapper: &W,
) {
    use rand::seq::SliceRandom;

    // Find first real proof
    let first_real_idx = proofs.iter().position(|p| !wrapper.is_dummy(p));

    if let Some(idx) = first_real_idx {
        proofs.swap(0, idx);
    }
    // If no real proof found (all dummies), leave as-is - circuit handles this case

    // Shuffle remaining proofs (positions 1..N) with external randomness
    if proofs.len() > 1 {
        let mut rng = rand::thread_rng();
        proofs[1..].shuffle(&mut rng);
    }
}
