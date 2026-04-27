use anyhow::{anyhow, bail, Result};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_data::VerifierOnlyCircuitData, proof::ProofWithPublicInputs},
};
use zk_circuits_common::circuit::{C, D, F};

use crate::layer0::{
    circuit::constants::OUTER_INNER_PROOFS,
    circuit::{inner::InnerAggregationCircuitTargets, outer::OuterAggregationCircuitTargets},
};

pub fn fill_inner_aggregation_witness(
    pw: &mut PartialWitness<F>,
    targets: &InnerAggregationCircuitTargets,
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

    pw.set_verifier_data_target(&targets.leaf_verifier_data, leaf_verifier_only)
        .map_err(|e| anyhow!("failed to set leaf verifier target: {}", e))?;

    for (i, (proof_t, proof)) in targets.leaf_proofs.iter().zip(proofs.iter()).enumerate() {
        pw.set_proof_with_pis_target(proof_t, proof)
            .map_err(|e| anyhow!("failed to set leaf proof target at slot {}: {}", i, e))?;
    }

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

pub fn fill_outer_aggregation_witness(
    pw: &mut PartialWitness<F>,
    targets: &OuterAggregationCircuitTargets,
    inner_verifier_only: &VerifierOnlyCircuitData<C, D>,
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    if proofs.len() != OUTER_INNER_PROOFS {
        bail!(
            "outer proof count mismatch: got {}, expected {}",
            proofs.len(),
            OUTER_INNER_PROOFS
        );
    }

    pw.set_verifier_data_target(&targets.inner_verifier_data, inner_verifier_only)
        .map_err(|e| anyhow!("failed to set inner verifier target: {}", e))?;

    for (idx, (proof_t, proof)) in targets.inner_proofs.iter().zip(proofs.iter()).enumerate() {
        pw.set_proof_with_pis_target(proof_t, proof)
            .map_err(|e| anyhow!("failed to set inner proof target {}: {}", idx, e))?;
    }

    Ok(())
}

pub use fill_inner_aggregation_witness as fill_layer0_aggregation_witness;
