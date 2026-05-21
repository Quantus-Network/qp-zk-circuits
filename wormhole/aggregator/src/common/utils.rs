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
    aggregated_output, ASSET_ID_START, BLOCK_HASH_START, EXIT_1_START, EXIT_2_START, LEAF_PI_LEN,
    OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START,
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

/// Enforce the layer-0 empty output-slot invariant for a leaf proof.
///
/// A zero exit-account digest is the empty-slot sentinel used by aggregation. To avoid silently
/// dropping value during deduplication, any output slot with a zero exit account must have amount 0.
pub fn validate_leaf_proof_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    label: &str,
) -> Result<()> {
    ensure_proof_public_input_len(proof, LEAF_PI_LEN, label)?;
    ensure_zero_exit_slot_has_zero_amount(
        proof.public_inputs[OUTPUT_AMOUNT_1_START],
        &proof.public_inputs[EXIT_1_START..EXIT_1_START + 4],
        &format!("{label} output slot 1"),
    )?;
    ensure_zero_exit_slot_has_zero_amount(
        proof.public_inputs[OUTPUT_AMOUNT_2_START],
        &proof.public_inputs[EXIT_2_START..EXIT_2_START + 4],
        &format!("{label} output slot 2"),
    )?;
    Ok(())
}

/// Enforce the same empty-slot invariant on an aggregated exit-slot region.
pub fn validate_aggregated_zero_exit_slots(
    public_inputs: &[F],
    slots_start: usize,
    slot_count: usize,
    slot_len: usize,
    label: &str,
) -> Result<()> {
    for slot in 0..slot_count {
        let base = slots_start + slot * slot_len;
        let end = base + slot_len;
        if public_inputs.len() < end {
            return Err(anyhow!(
                "{} public input length mismatch: slot {} needs end index {}, got {}",
                label,
                slot,
                end,
                public_inputs.len()
            ));
        }
        ensure_zero_exit_slot_has_zero_amount(
            public_inputs[base],
            &public_inputs[base + 1..base + 5],
            &format!("{label} exit slot {slot}"),
        )?;
    }
    Ok(())
}

fn ensure_zero_exit_slot_has_zero_amount(amount: F, exit_account: &[F], label: &str) -> Result<()> {
    if exit_account.len() != 4 {
        return Err(anyhow!(
            "{} exit account length mismatch: expected 4 felts, got {}",
            label,
            exit_account.len()
        ));
    }

    let exit_is_zero = exit_account.iter().all(|felt| felt.is_zero());
    if exit_is_zero && !amount.is_zero() {
        return Err(anyhow!(
            "{} has zero exit_account but non-zero output amount {}; zero exit accounts are reserved for empty output slots",
            label,
            amount.to_canonical_u64()
        ));
    }

    Ok(())
}

pub fn leaf_proof_asset_id(proof: &ProofWithPublicInputs<F, C, D>) -> Result<u32> {
    validate_leaf_proof_public_inputs(proof, "leaf proof")?;
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
