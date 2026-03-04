use anyhow::{anyhow, Result};
use plonky2::{
    plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
    util::serialization::DefaultGateSerializer,
};
use zk_circuits_common::circuit::{C, D, F};

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
