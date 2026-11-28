//! Witness filling for the public-batch aggregation circuit.
//!
//! Crate-private: callers with untrusted proof vectors must go through
//! [`super::PublicBatchProver::build_witness`], which verifies each inner proof,
//! enforces metadata compatibility, pads only after validation, and rejects
//! all-dummy batches before this helper runs.

use anyhow::{bail, Result};
#[cfg(feature = "gpu")]
use plonky2::{field::types::Field, iop::target::Target};
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::proof::ProofWithPublicInputs;

use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::Digest;

use crate::common::utils::ensure_proof_shape_matches_targets;
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuitTargets;

/// Write private-batch proofs and the aggregator address through a witness writer.
///
/// Structural checks only (proof count + shape). Not safe for untrusted inputs
/// on its own — see the module docs.
pub(crate) fn fill_public_batch_witness<'a, I>(
    pw: &mut impl WitnessWrite<F>,
    targets: &PublicBatchCircuitTargets,
    private_batch_proofs: I,
    aggregator_address: Digest,
) -> Result<()>
where
    I: IntoIterator<Item = &'a ProofWithPublicInputs<F, C, D>>,
    I::IntoIter: ExactSizeIterator,
{
    let private_batch_proofs = private_batch_proofs.into_iter();
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
        .zip(private_batch_proofs)
        .enumerate()
    {
        // Full proof-shape preflight at this Result boundary: a malformed
        // proof (wrong PI count, truncated FRI query rounds, inconsistent
        // opening vectors, ...) would otherwise panic inside plonky2's
        // witness writer or silently leave targets unset.
        ensure_proof_shape_matches_targets(proof_t, proof, i, "private-batch proof")?;
        pw.set_proof_with_pis_target(proof_t, proof)?;
    }

    Ok(())
}

/// Collects the input targets assigned by public-batch witness filling.
#[cfg(feature = "gpu")]
pub(super) fn public_batch_input_targets(
    targets: &PublicBatchCircuitTargets,
    dummy_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<Vec<Target>> {
    struct InputTargets(Vec<Target>);

    impl WitnessWrite<F> for InputTargets {
        fn set_target(&mut self, target: Target, _value: F) -> Result<()> {
            self.0.push(target);
            Ok(())
        }
    }

    let mut inputs = InputTargets(Vec::new());
    let proofs = (0..targets.private_batch_proofs.len()).map(|_| dummy_proof);
    fill_public_batch_witness(
        &mut inputs,
        targets,
        proofs,
        targets.aggregator_address.map(|_| F::ZERO),
    )?;
    Ok(inputs.0)
}
