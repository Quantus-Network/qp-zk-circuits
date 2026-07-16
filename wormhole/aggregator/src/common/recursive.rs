//! Safe recursive proof verification utilities.
//!
//! This module provides helpers for recursively verifying proofs in a way that
//! prevents verifier key substitution attacks.
//!
//! ## Security Background
//!
//! When verifying a proof recursively (inside another circuit), you need both:
//! 1. The proof itself
//! 2. The verifier key (circuit digest + merkle cap)
//!
//! There are two ways to handle the verifier key:
//!
//! ### UNSAFE: Virtual (witness) verifier key
//! ```ignore
//! let vk = builder.add_virtual_verifier_data(cap_height);  // UNSAFE!
//! builder.verify_proof(&proof, &vk, &common);
//! ```
//! This allows the prover to substitute ANY verifier key, enabling them to
//! verify proofs from malicious circuits with no constraints.
//!
//! ### SAFE: Constant verifier key
//! ```ignore
//! let vk = builder.constant_verifier_data(&expected_verifier_only);  // SAFE!
//! builder.verify_proof(&proof, &vk, &common);
//! ```
//! This bakes the expected verifier key as constants, ensuring only proofs
//! from the intended circuit can be verified.
//!
//! ## Usage
//!
//! Use [`add_recursive_verifiers`] to safely add recursive verification:
//!
//! ```ignore
//! // Multiple proofs from the same circuit
//! let proof_targets = add_recursive_verifiers(&mut builder, &inner_common, &inner_vk, n)?;
//! ```

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputsTarget,
    },
};
use qp_wormhole_inputs::validate_proof_count;

/// Safely add multiple recursive proof verifications for the same inner circuit.
///
/// All proofs are verified against the same constant verifier key.
///
/// # Arguments
///
/// * `builder` - The circuit builder
/// * `inner_common` - Common circuit data of the inner circuit
/// * `inner_verifier_only` - Verifier-only data of the inner circuit (baked as constants)
/// * `num_proofs` - Number of proofs to verify
///
/// # Returns
///
/// A vector of proof targets (the only witnesses needed).
///
/// # Errors
///
/// Returns an error when `num_proofs` is outside `1..=MAX_PROOF_COUNT`. The
/// bound is enforced here — not only in the higher-level batch constructors —
/// because this is a public API boundary: `num_proofs` drives allocation and
/// per-proof recursive-verifier construction, and `0` would silently produce
/// an outer circuit with no inner-proof constraints at all.
pub fn add_recursive_verifiers<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    inner_common: &CommonCircuitData<F, D>,
    inner_verifier_only: &VerifierOnlyCircuitData<C, D>,
    num_proofs: usize,
) -> Result<Vec<ProofWithPublicInputsTarget<D>>>
where
    C::Hasher: AlgebraicHasher<F>,
    C::InnerHasher: AlgebraicHasher<F>,
{
    validate_proof_count(num_proofs, "num_proofs")?;

    // SECURITY: Bake the verifier key as constants (shared across all proofs).
    let verifier_data = builder.constant_verifier_data::<C>(inner_verifier_only);

    // Add virtual proof targets and verification for each
    let mut proofs = Vec::with_capacity(num_proofs);
    for _ in 0..num_proofs {
        let proof = builder.add_virtual_proof_with_pis(inner_common);
        builder.verify_proof::<C>(&proof, &verifier_data, inner_common);
        proofs.push(proof);
    }

    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::circuit_data::CircuitConfig,
    };
    use zk_circuits_common::circuit::{C, D, F};

    /// The proof-count invariant must hold at this public boundary: zero would
    /// build an outer circuit with no inner-proof constraints, and an
    /// unbounded count drives allocation and circuit-construction work.
    #[test]
    fn rejects_out_of_range_proof_counts() {
        use qp_wormhole_inputs::MAX_PROOF_COUNT;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let t = builder.add_virtual_target();
        builder.register_public_input(t);
        let inner = builder.build::<C>();

        for bad_count in [0, MAX_PROOF_COUNT + 1] {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            let err = add_recursive_verifiers::<F, C, D>(
                &mut builder,
                &inner.common,
                &inner.verifier_only,
                bad_count,
            )
            .expect_err("out-of-range num_proofs must be rejected");
            assert!(
                err.to_string().contains("num_proofs"),
                "got: {err} for count {bad_count}"
            );
        }
    }

    #[test]
    fn test_safe_recursive_verifier_rejects_wrong_circuit() {
        // Build a "legitimate" inner circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let t = builder.add_virtual_target();
        builder.register_public_input(t);
        builder.range_check(t, 16); // Real constraint
        let legit_circuit = builder.build::<C>();

        // Build a "malicious" inner circuit (same shape, no constraints)
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let t = builder.add_virtual_target();
        builder.register_public_input(t);
        // NO constraints!
        let malicious_circuit = builder.build::<C>();

        // Build outer circuit using SAFE helper with legitimate verifier key
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let proof_targets = add_recursive_verifiers::<F, C, D>(
            &mut builder,
            &legit_circuit.common,
            &legit_circuit.verifier_only, // Baked as constants
            1,
        )
        .unwrap();
        let proof_target = &proof_targets[0];
        builder.register_public_inputs(&proof_target.public_inputs);
        let outer_circuit = builder.build::<C>();

        // Generate a malicious proof
        let mut pw = PartialWitness::new();
        // Keep the public input valid for the legitimate circuit; only the verifier key should differ.
        pw.set_target(
            malicious_circuit.prover_only.public_inputs[0],
            F::from_canonical_u64(100),
        )
        .unwrap();
        let malicious_proof = malicious_circuit.prove(pw).expect("malicious prove");

        // Try to use malicious proof in outer circuit
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(proof_target, &malicious_proof)
            .unwrap();
        // Note: We do NOT set verifier_data - it's constants!

        // This should FAIL because the proof doesn't match the baked verifier key
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| outer_circuit.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "Should reject proof from wrong circuit"
        );
    }

    #[test]
    fn test_safe_recursive_verifier_accepts_correct_circuit() {
        // Build inner circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let t = builder.add_virtual_target();
        builder.register_public_input(t);
        builder.range_check(t, 16);
        let inner_circuit = builder.build::<C>();

        // Build outer circuit using SAFE helper
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let proof_targets = add_recursive_verifiers::<F, C, D>(
            &mut builder,
            &inner_circuit.common,
            &inner_circuit.verifier_only,
            1,
        )
        .unwrap();
        let proof_target = &proof_targets[0];
        builder.register_public_inputs(&proof_target.public_inputs);
        let outer_circuit = builder.build::<C>();

        // Generate a legitimate proof
        let mut pw = PartialWitness::new();
        pw.set_target(
            inner_circuit.prover_only.public_inputs[0],
            F::from_canonical_u64(100),
        )
        .unwrap();
        let legit_proof = inner_circuit.prove(pw).expect("legit prove");

        // Use legitimate proof in outer circuit
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(proof_target, &legit_proof)
            .unwrap();

        // This should SUCCEED
        let outer_proof = outer_circuit.prove(pw).expect("outer prove should succeed");
        outer_circuit
            .verify(outer_proof)
            .expect("outer verify should succeed");
    }
}
