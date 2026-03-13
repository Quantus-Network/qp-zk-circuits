//! Witness filling for the layer-1 aggregation circuit.

use anyhow::{bail, Result};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::{circuit_data::VerifierOnlyCircuitData, proof::ProofWithPublicInputs};

use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{felts_to_hashout, Digest};

use crate::layer1::circuit::circuit_logic::Layer1AggregationCircuitTargets;

/// Fill a partial witness for the layer-1 aggregation circuit.
///
/// This is the single source of truth used by `Layer1AggregationProver::commit(...)`.
pub fn fill_layer1_aggregation_witness(
    pw: &mut PartialWitness<F>,
    targets: &Layer1AggregationCircuitTargets,
    layer0_verifier_only: &VerifierOnlyCircuitData<C, D>,
    layer0_proofs: &[ProofWithPublicInputs<F, C, D>],
    aggregator_address: Digest,
) -> Result<()> {
    if layer0_proofs.len() != targets.layer0_proofs.len() {
        bail!(
            "layer1 witness fill expected {} layer0 proofs, got {}",
            targets.layer0_proofs.len(),
            layer0_proofs.len()
        );
    }

    pw.set_hash_target(
        targets.aggregator_address,
        felts_to_hashout(&aggregator_address),
    )?;
    pw.set_verifier_data_target(&targets.layer0_verifier_data, layer0_verifier_only)?;

    for (proof_t, proof) in targets.layer0_proofs.iter().zip(layer0_proofs.iter()) {
        pw.set_proof_with_pis_target(proof_t, proof)?;
    }

    Ok(())
}
