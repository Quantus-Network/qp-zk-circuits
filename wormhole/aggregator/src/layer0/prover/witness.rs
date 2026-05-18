use anyhow::{anyhow, bail, Result};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::proof::ProofWithPublicInputs,
};
use zk_circuits_common::circuit::{C, D, F};

use crate::layer0::circuit::{
    constants::{INNER_NUM_LEAVES, OUTER_INNER_PROOFS},
    inner::InnerAggregationCircuitTargets,
    outer::OuterAggregationCircuitTargets,
};

pub fn fill_inner_aggregation_witness(
    pw: &mut PartialWitness<F>,
    targets: &InnerAggregationCircuitTargets,
    proofs: &[ProofWithPublicInputs<F, C, D>],
    dummy_nullifier_pre_images: &[[F; 4]],
) -> Result<()> {
    if targets.leaf_proofs.len() != INNER_NUM_LEAVES {
        bail!(
            "inner target layout is inconsistent: got {} leaf proof targets, expected {}",
            targets.leaf_proofs.len(),
            INNER_NUM_LEAVES
        );
    }

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

    for (i, (proof_t, proof)) in targets.leaf_proofs.iter().zip(proofs.iter()).enumerate() {
        if proof.public_inputs.len() != proof_t.public_inputs.len() {
            bail!(
                "leaf proof public input length mismatch at slot {}: got {}, target expects {}",
                i,
                proof.public_inputs.len(),
                proof_t.public_inputs.len()
            );
        }
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
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    if targets.inner_proofs.len() != OUTER_INNER_PROOFS {
        bail!(
            "outer target layout is inconsistent: got {} inner proof targets, expected {}",
            targets.inner_proofs.len(),
            OUTER_INNER_PROOFS
        );
    }
    if proofs.len() != OUTER_INNER_PROOFS {
        bail!(
            "outer proof count mismatch: got {}, expected {}",
            proofs.len(),
            OUTER_INNER_PROOFS
        );
    }

    for (idx, (proof_t, proof)) in targets.inner_proofs.iter().zip(proofs.iter()).enumerate() {
        if proof.public_inputs.len() != proof_t.public_inputs.len() {
            bail!(
                "inner proof public input length mismatch at slot {}: got {}, target expects {}",
                idx,
                proof.public_inputs.len(),
                proof_t.public_inputs.len()
            );
        }
        pw.set_proof_with_pis_target(proof_t, proof)
            .map_err(|e| anyhow!("failed to set inner proof target {}: {}", idx, e))?;
    }

    Ok(())
}

pub use fill_inner_aggregation_witness as fill_layer0_aggregation_witness;
