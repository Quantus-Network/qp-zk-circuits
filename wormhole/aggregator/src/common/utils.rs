use anyhow::{anyhow, bail, Result};
use plonky2::{
    field::types::Field,
    field::types::PrimeField64,
    plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
    plonk::proof::ProofWithPublicInputs,
    util::serialization::DefaultGateSerializer,
};
use rand::seq::SliceRandom;
use zk_circuits_common::circuit::{C, D, F};

use crate::layer0::circuit::constants::{
    aggregated_output, ASSET_ID_START, BLOCK_HASH_START, LEAF_PI_LEN,
};

/// Load verifier circuit data (common + verifier-only) from serialized bytes.
pub fn load_verifier_data_from_bytes(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    label: &str,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
        .map_err(|e| anyhow!("Failed to deserialize {} common data: {}", label, e))?;

    let verifier_only =
        VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes.to_vec())
            .map_err(|e| anyhow!("Failed to deserialize {} verifier-only data: {}", label, e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
}

pub fn ensure_proof_public_input_len(
    proof: &ProofWithPublicInputs<F, C, D>,
    expected_len: usize,
    label: &str,
) -> Result<()> {
    let actual_len = proof.public_inputs.len();
    if actual_len != expected_len {
        return Err(anyhow!(
            "{} public input length mismatch: expected {}, got {}",
            label,
            expected_len,
            actual_len
        ));
    }

    Ok(())
}

pub fn leaf_proof_asset_id(proof: &ProofWithPublicInputs<F, C, D>) -> Result<u32> {
    ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
    proof.public_inputs[ASSET_ID_START]
        .to_canonical_u64()
        .try_into()
        .map_err(|_| anyhow!("leaf proof asset_id exceeds u32 range"))
}

pub fn is_dummy_leaf_proof(proof: &ProofWithPublicInputs<F, C, D>) -> Result<bool> {
    ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
    Ok(proof.public_inputs[BLOCK_HASH_START..BLOCK_HASH_START + 4]
        .iter()
        .all(|f| f.is_zero()))
}

pub fn l0_num_leaves_from_padded_pi_len(pi_len: usize) -> Result<usize> {
    if pi_len < aggregated_output::HEADER_LEN {
        return Err(anyhow!(
            "layer-0 aggregated public input length {} is smaller than the fixed header {}",
            pi_len,
            aggregated_output::HEADER_LEN
        ));
    }

    let payload_len = pi_len - aggregated_output::HEADER_LEN;
    if !payload_len.is_multiple_of(LEAF_PI_LEN) {
        return Err(anyhow!(
            "layer-0 aggregated public input length {} is malformed: expected {} + N*{}",
            pi_len,
            aggregated_output::HEADER_LEN,
            LEAF_PI_LEN
        ));
    }

    let num_leaves = payload_len / LEAF_PI_LEN;
    if num_leaves == 0 {
        return Err(anyhow!(
            "layer-0 aggregated public input length {} encodes zero leaves",
            pi_len
        ));
    }

    Ok(num_leaves)
}

// -----------------------------------------------------------------------------
// Layer-0 proof padding/shuffling helpers
// -----------------------------------------------------------------------------

/// Shuffle leaf proofs while ensuring a real proof remains in slot 0 (if any real proof exists).
///
/// This is required because the layer-0 circuit derives its public outputs (block_hash, etc.)
/// from slot 0. If a dummy proof (with zeroed block_hash) ends up in slot 0, the aggregated
/// proof would have invalid public outputs.
pub fn shuffle_proofs_preserving_first_real(proofs: &mut [ProofWithPublicInputs<F, C, D>]) {
    // Find the first real proof and swap it to position 0
    if let Some(first_real_idx) = proofs
        .iter()
        .position(|p| !is_dummy_leaf_proof(p).unwrap_or(false))
    {
        proofs.swap(0, first_real_idx);
    }

    // Shuffle remaining proofs (positions 1..n)
    if proofs.len() > 1 {
        let mut rng = rand::thread_rng();
        proofs[1..].shuffle(&mut rng);
    }
}

/// Verify that all real proofs use `asset_id = 0` when padding with dummy proofs is required.
///
/// This check is necessary because:
/// - Dummy proofs use `asset_id = 0`
/// - The layer-0 circuit enforces `asset_id` equality across all proofs
/// - Mixing non-zero `asset_id` real proofs with dummy proofs would fail in-circuit
pub fn assert_dummy_padding_asset_id_compatible(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    for (idx, proof) in proofs.iter().enumerate() {
        ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
        let real_asset_id = leaf_proof_asset_id(proof)?;

        if real_asset_id != 0 {
            bail!(
                "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                 All proofs must have the same asset_id for aggregation when padding is required.",
                idx,
                real_asset_id
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::l0_num_leaves_from_padded_pi_len;

    #[test]
    fn l0_num_leaves_from_padded_pi_len_rejects_malformed_lengths() {
        let err = l0_num_leaves_from_padded_pi_len(9).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }
}
