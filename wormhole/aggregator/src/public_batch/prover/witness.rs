//! Witness filling for the public-batch aggregation circuit.

use anyhow::{bail, Result};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::proof::ProofWithPublicInputs;

use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::Digest;

use crate::public_batch::circuit::circuit_logic::PublicBatchCircuitTargets;

/// Fill a partial witness for the public-batch aggregation circuit.
pub fn fill_public_batch_witness(
    pw: &mut PartialWitness<F>,
    targets: &PublicBatchCircuitTargets,
    private_batch_proofs: &[ProofWithPublicInputs<F, C, D>],
    aggregator_address: Digest,
) -> Result<()> {
    if private_batch_proofs.len() != targets.private_batch_proofs.len() {
        bail!(
            "public_batch witness fill expected {} private_batch proofs, got {}",
            targets.private_batch_proofs.len(),
            private_batch_proofs.len()
        );
    }

    for (target, value) in targets
        .aggregator_address
        .iter()
        .zip(aggregator_address.iter())
    {
        pw.set_target(*target, *value)?;
    }

    for (i, (proof_t, proof)) in targets
        .private_batch_proofs
        .iter()
        .zip(private_batch_proofs.iter())
        .enumerate()
    {
        // Reject shape mismatches at this Result boundary: with fewer public
        // inputs than targets, set_proof_with_pis_target's internal zip would
        // silently leave trailing PI targets unset instead of erroring.
        if proof.public_inputs.len() != proof_t.public_inputs.len() {
            bail!(
                "private-batch proof at slot {} has {} public inputs, but the circuit expects {}",
                i,
                proof.public_inputs.len(),
                proof_t.public_inputs.len()
            );
        }
        pw.set_proof_with_pis_target(proof_t, proof)?;
    }

    Ok(())
}
