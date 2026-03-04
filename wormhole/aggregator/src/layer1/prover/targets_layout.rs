use anyhow::{Context, Result};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use serde::{Deserialize, Serialize};

use zk_circuits_common::circuit::D;

use crate::common::targets_layout::{
    HashOutTargetLayout, ProofWithPublicInputsTargetLayout, VerifierCircuitTargetLayout,
};
use crate::layer1::circuit::Layer1AggregationCircuitTargets;

/// Reconstructed runtime targets used by the layer-1 prover witness filler.
#[derive(Debug, Clone)]
pub struct Layer1RuntimeTargets<const D2: usize> {
    pub layer0_verifier_data_t: VerifierCircuitTarget,
    pub layer0_proof_targets: Vec<ProofWithPublicInputsTarget<D2>>,
    pub aggregator_address_targets: HashOutTarget,
}

/// Serializable target layout for the layer-1 aggregation circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer1TargetsLayout<const D2: usize> {
    pub n_layer0: usize,
    pub layer0_verifier_data_t: VerifierCircuitTargetLayout,
    pub layer0_proof_targets: Vec<ProofWithPublicInputsTargetLayout<D2>>,
    pub aggregator_address_targets: HashOutTargetLayout,
}

pub type Layer1TargetsLayoutD = Layer1TargetsLayout<D>;

impl<const D2: usize> Layer1TargetsLayout<D2> {
    /// Build serializable layout from runtime targets.
    pub fn from_runtime(
        n_layer0: usize,
        layer0_verifier_data_t: &VerifierCircuitTarget,
        layer0_proof_targets: &[ProofWithPublicInputsTarget<D2>],
        aggregator_address_targets: &HashOutTarget,
    ) -> Result<Self> {
        Ok(Self {
            n_layer0,
            layer0_verifier_data_t: VerifierCircuitTargetLayout::from_runtime(
                layer0_verifier_data_t,
            )?,
            layer0_proof_targets: layer0_proof_targets
                .iter()
                .map(ProofWithPublicInputsTargetLayout::from_runtime)
                .collect::<Result<Vec<_>>>()?,
            aggregator_address_targets: HashOutTargetLayout::from_runtime(
                aggregator_address_targets,
            )?,
        })
    }

    /// Reconstruct runtime targets from serialized layout.
    pub fn to_runtime(&self) -> Result<Layer1RuntimeTargets<D2>> {
        let proofs = self
            .layer0_proof_targets
            .iter()
            .map(|p| {
                p.to_runtime()
                    .context("failed to reconstruct layer0 proof target")
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Layer1RuntimeTargets {
            // IMPORTANT: `to_runtime()` here returns the value directly, not a Result
            layer0_verifier_data_t: self.layer0_verifier_data_t.to_runtime(),
            layer0_proof_targets: proofs,
            aggregator_address_targets: self.aggregator_address_targets.to_runtime(),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).context("failed to serialize layer1 targets layout")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("failed to deserialize layer1 targets layout")
    }
}

impl From<&Layer1AggregationCircuitTargets> for Layer1TargetsLayoutD {
    fn from(targets: &Layer1AggregationCircuitTargets) -> Self {
        Self::from_runtime(
            targets.layer0_proofs.len(),
            &targets.layer0_verifier_data,
            &targets.layer0_proofs,
            &targets.aggregator_address,
        )
        .unwrap()
    }
}
