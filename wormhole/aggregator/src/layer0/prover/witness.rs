//! Witness filling for the prebuilt layer-0 aggregation prover.

use anyhow::{anyhow, bail, Result};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_data::VerifierOnlyCircuitData, proof::ProofWithPublicInputs},
};

use zk_circuits_common::circuit::{C, D, F};

use crate::layer0::circuit::circuit_logic::AggregationCircuitTargets;

/// Fill the partial witness for the prebuilt layer-0 aggregation circuit.
///
/// This is the single source of truth for witness-filling logic used by
/// `Layer0AggregationProver::commit(...)`.
///
/// It sets:
/// - the leaf verifier target (`add_virtual_verifier_data`)
/// - all leaf proof targets (`add_virtual_proof_with_pis`)
/// - all dummy nullifier preimage targets (hashed only for dummy slots in-circuit)
///
/// # Arguments
/// * `pw` - Partial witness to fill
/// * `targets` - Runtime targets reconstructed from circuit
/// * `leaf_verifier_only` - Verifier data for the leaf wormhole circuit
/// * `proofs` - Exactly N leaf proofs (already padded/shuffled by the prover)
/// * `dummy_nullifier_pre_images` - Exactly N dummy nullifier preimages (one per slot)
pub fn fill_layer0_aggregation_witness(
    pw: &mut PartialWitness<F>,
    targets: &AggregationCircuitTargets,
    leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
    proofs: &[ProofWithPublicInputs<F, C, D>],
    dummy_nullifier_pre_images: &[[F; 4]],
) -> Result<()> {
    let n_targets = targets.leaf_proofs.len();

    if proofs.len() != n_targets {
        bail!(
            "proof count mismatch: got {}, but circuit expects {} leaf proofs",
            proofs.len(),
            n_targets
        );
    }

    if targets.dummy_nullifier_pre_images.len() != n_targets {
        bail!(
            "target layout is inconsistent: dummy_nullifier_pre_image target count {} != leaf proof target count {}",
            targets.dummy_nullifier_pre_images.len(),
            n_targets
        );
    }

    if dummy_nullifier_pre_images.len() != n_targets {
        bail!(
            "dummy nullifier preimage count mismatch: got {}, but circuit expects {}",
            dummy_nullifier_pre_images.len(),
            n_targets
        );
    }

    // Fill the leaf verifier target used by builder.verify_proof(...)
    pw.set_verifier_data_target(&targets.leaf_verifier_data, leaf_verifier_only)
        .map_err(|e| anyhow!("failed to set leaf verifier target: {}", e))?;

    // Fill each leaf proof target
    for (i, (proof_t, proof)) in targets.leaf_proofs.iter().zip(proofs.iter()).enumerate() {
        pw.set_proof_with_pis_target(proof_t, proof)
            .map_err(|e| anyhow!("failed to set leaf proof target at slot {}: {}", i, e))?;
    }

    // Fill dummy nullifier preimage targets (the circuit hashes these only for dummy proofs)
    for (i, (nullifier_targets, nullifier_vals)) in targets
        .dummy_nullifier_pre_images
        .iter()
        .zip(dummy_nullifier_pre_images.iter())
        .enumerate()
    {
        for limb in 0..4 {
            pw.set_target(nullifier_targets[limb], nullifier_vals[limb])
                .map_err(|e| {
                    anyhow!(
                        "failed to set dummy nullifier preimage target at slot {}, limb {}: {}",
                        i,
                        limb,
                        e
                    )
                })?;
        }
    }

    Ok(())
}
