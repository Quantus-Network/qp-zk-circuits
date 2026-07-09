use anyhow::{anyhow, bail, Result};
use plonky2::{
    field::types::PrimeField64,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
    util::serialization::DefaultGateSerializer,
};
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::{
    wormhole_leaf_circuit_config, wormhole_private_batch_circuit_config,
    wormhole_public_batch_circuit_config, C, D, F,
};

use crate::private_batch::circuit::{
    circuit_logic::PrivateBatchCircuit,
    constants::{aggregated_output, ASSET_ID_START, LEAF_PI_LEN, VOLUME_FEE_BPS_START},
};
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;

/// Load verifier circuit data (common + verifier-only) from serialized bytes.
///
/// When `canonical` is provided, the loaded artifacts are pinned to that exact
/// verifier data (byte-identical common + verifier-only).
pub fn load_verifier_data_from_bytes(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    label: &str,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
        .map_err(|e| anyhow!("failed to deserialize {} common data: {}", label, e))?;

    let verifier_only =
        VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes.to_vec())
            .map_err(|e| anyhow!("failed to deserialize {} verifier-only data: {}", label, e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
}

/// Load leaf verifier data and reject anything that is not the canonical Wormhole leaf circuit.
pub fn load_canonical_leaf_verifier_data(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
) -> Result<VerifierCircuitData<F, C, D>> {
    let loaded = load_verifier_data_from_bytes(common_bytes, verifier_only_bytes, "leaf")?;
    ensure_verifier_data_matches_canonical(
        &loaded,
        &canonical_leaf_verifier_data(),
        "leaf",
    )?;
    Ok(loaded)
}

/// Load private-batch verifier data pinned to the canonical private-batch circuit for `num_leaf_proofs`.
pub fn load_canonical_private_batch_verifier_data(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    let loaded = load_verifier_data_from_bytes(common_bytes, verifier_only_bytes, "private_batch")?;
    let leaf = canonical_leaf_verifier_data();
    let canonical = canonical_private_batch_verifier_data(&leaf, num_leaf_proofs);
    ensure_verifier_data_matches_canonical(&loaded, &canonical, "private_batch")?;
    Ok(loaded)
}

pub fn ensure_common_matches_canonical(
    loaded: &CommonCircuitData<F, D>,
    canonical: &CommonCircuitData<F, D>,
    label: &str,
) -> Result<()> {
    ensure_config_is_canonical(&loaded.config, &canonical.config, label)?;

    let gate_serializer = DefaultGateSerializer;
    let loaded_bytes = loaded
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize loaded {} common data: {}", label, e))?;
    let canonical_bytes = canonical
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize canonical {} common data: {}", label, e))?;

    if loaded_bytes != canonical_bytes {
        bail!(
            "loaded {} common circuit data does not match the canonical circuit",
            label
        );
    }

    Ok(())
}

pub fn ensure_verifier_data_matches_canonical(
    loaded: &VerifierCircuitData<F, C, D>,
    canonical: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<()> {
    ensure_common_matches_canonical(&loaded.common, &canonical.common, label)?;

    let loaded_vo = loaded
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize loaded {} verifier-only data: {}", label, e))?;
    let canonical_vo = canonical.verifier_only.to_bytes().map_err(|e| {
        anyhow!(
            "failed to serialize canonical {} verifier-only data: {}",
            label,
            e
        )
    })?;

    if loaded_vo != canonical_vo {
        bail!(
            "loaded {} verifier-only data does not match the canonical circuit",
            label
        );
    }

    Ok(())
}

pub fn ensure_config_is_canonical(
    loaded: &CircuitConfig,
    expected: &CircuitConfig,
    label: &str,
) -> Result<()> {
    if loaded != expected {
        bail!(
            "loaded {} circuit config does not match the canonical Wormhole config \
             (security_bits loaded={}, expected={})",
            label,
            loaded.security_bits,
            expected.security_bits
        );
    }
    Ok(())
}

pub fn canonical_leaf_verifier_data() -> VerifierCircuitData<F, C, D> {
    WormholeCircuit::new(wormhole_leaf_circuit_config()).build_verifier()
}

pub fn canonical_private_batch_verifier_data(
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaf_proofs: usize,
) -> VerifierCircuitData<F, C, D> {
    PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf.common,
        &leaf.verifier_only,
        num_leaf_proofs,
    )
    .build_verifier()
}

pub fn canonical_public_batch_verifier_data(
    private_batch: &VerifierCircuitData<F, C, D>,
    num_private_batch_proofs: usize,
    num_leaf_proofs: usize,
) -> VerifierCircuitData<F, C, D> {
    PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private_batch.common.clone(),
        &private_batch.verifier_only,
        num_private_batch_proofs,
        num_leaf_proofs,
    )
    .build_verifier()
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

pub fn leaf_proof_volume_fee_bps(proof: &ProofWithPublicInputs<F, C, D>) -> Result<u32> {
    ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
    proof.public_inputs[VOLUME_FEE_BPS_START]
        .to_canonical_u64()
        .try_into()
        .map_err(|_| anyhow!("leaf proof volume_fee_bps exceeds u32 range"))
}

pub fn private_batch_num_leaves_from_padded_pi_len(pi_len: usize) -> Result<usize> {
    if pi_len < aggregated_output::HEADER_LEN {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is smaller than the fixed header {}",
            pi_len,
            aggregated_output::HEADER_LEN
        ));
    }

    let payload_len = pi_len - aggregated_output::HEADER_LEN;
    if !payload_len.is_multiple_of(LEAF_PI_LEN) {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is malformed: expected {} + N*{}",
            pi_len,
            aggregated_output::HEADER_LEN,
            LEAF_PI_LEN
        ));
    }

    let num_leaves = payload_len / LEAF_PI_LEN;
    if num_leaves == 0 {
        return Err(anyhow!(
            "private-batch aggregated public input length {} encodes zero leaves",
            pi_len
        ));
    }

    Ok(num_leaves)
}

#[cfg(test)]
mod tests {
    use super::private_batch_num_leaves_from_padded_pi_len;

    #[test]
    fn private_batch_num_leaves_from_padded_pi_len_rejects_malformed_lengths() {
        let err = private_batch_num_leaves_from_padded_pi_len(9).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }
}
