use anyhow::bail;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

use crate::dummy_proof::generate_dummy_proof;

/// Pads a vector of proofs with dummy proofs to reach the required length.
///
/// Each dummy proof has a unique random nullifier, providing privacy by making
/// it impossible to distinguish dummy proofs from real ones based on nullifier
/// patterns. Dummy proofs use `block_hash = 0` as a sentinel, so they are
/// excluded from block validation in the aggregator.
pub fn pad_with_dummy_proofs(
    mut proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    proof_len: usize,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>> {
    let num_proofs = proofs.len();

    if num_proofs > proof_len {
        bail!("proofs to aggregate was more than the maximum allowed")
    }

    let zk = common_data.config.zero_knowledge;
    let num_dummies_needed = proof_len - num_proofs;

    if num_dummies_needed == 0 {
        return Ok(proofs);
    }

    // Generate dummy proofs with random nullifiers for privacy
    for _ in 0..num_dummies_needed {
        let dummy_proof = generate_dummy_proof(zk)?;
        proofs.push(dummy_proof);
    }

    Ok(proofs)
}
