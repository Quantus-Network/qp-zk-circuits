use anyhow::{anyhow, Result};
use plonky2::{
    field::types::Field,
    field::types::PrimeField64,
    plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
    plonk::proof::ProofWithPublicInputs,
    util::serialization::DefaultGateSerializer,
};
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

#[cfg(test)]
mod tests {
    use super::l0_num_leaves_from_padded_pi_len;

    #[test]
    fn l0_num_leaves_from_padded_pi_len_rejects_malformed_lengths() {
        let err = l0_num_leaves_from_padded_pi_len(9).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }
}
