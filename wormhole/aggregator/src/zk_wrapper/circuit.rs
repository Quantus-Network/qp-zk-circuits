//! ZK Wrapper circuit definition.
//!
//! A minimal ZK circuit that verifies a single non-ZK proof and forwards its public inputs.

use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::{
        CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
        VerifierCircuitTarget,
    },
    proof::ProofWithPublicInputsTarget,
};

use zk_circuits_common::circuit::{C, D, F};

/// Runtime targets for the ZK wrapper circuit.
#[derive(Debug, Clone)]
pub struct ZkWrapperTargets {
    /// Verifier target for the inner (non-ZK L0) circuit.
    pub inner_verifier_data: VerifierCircuitTarget,
    /// The inner proof to verify.
    pub inner_proof: ProofWithPublicInputsTarget<D>,
}

/// A simple ZK wrapper circuit that verifies a non-ZK proof and forwards its PIs.
pub struct ZkWrapperCircuit {
    builder: CircuitBuilder<F, D>,
    targets: ZkWrapperTargets,
}

impl ZkWrapperCircuit {
    /// Build a ZK wrapper circuit for a given inner circuit.
    ///
    /// # Arguments
    /// - `config`: circuit config for the wrapper (should have `zero_knowledge: true`)
    /// - `inner_common`: common data for the inner (non-ZK) circuit
    pub fn new(config: CircuitConfig, inner_common: CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Allocate verifier target for the inner circuit
        let inner_verifier_data =
            builder.add_virtual_verifier_data(inner_common.fri_params.config.cap_height);

        // Allocate proof target and verify it
        let inner_proof = builder.add_virtual_proof_with_pis(&inner_common);
        builder.verify_proof::<C>(&inner_proof, &inner_verifier_data, &inner_common);

        // Forward all public inputs from the inner proof
        builder.register_public_inputs(&inner_proof.public_inputs);

        let targets = ZkWrapperTargets {
            inner_verifier_data,
            inner_proof,
        };

        Self { builder, targets }
    }

    /// Get the circuit targets (for witness filling).
    pub fn targets(&self) -> ZkWrapperTargets {
        self.targets.clone()
    }

    /// Build and return the full circuit data.
    pub fn build_circuit(self) -> CircuitData<F, C, D> {
        self.builder.build::<C>()
    }

    /// Build and return only prover circuit data (more efficient if verifier not needed).
    pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
        self.builder.build_prover::<C>()
    }

    /// Build and return only verifier circuit data.
    pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
        self.builder.build_verifier::<C>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;

    #[test]
    fn test_wrapper_circuit_builds() {
        // Create a simple inner circuit to test with
        let inner_config = CircuitConfig::standard_recursion_config();
        let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);

        // Add some public inputs to the inner circuit
        let t1 = inner_builder.add_virtual_target();
        let t2 = inner_builder.add_virtual_target();
        inner_builder.register_public_input(t1);
        inner_builder.register_public_input(t2);

        let inner_data = inner_builder.build::<C>();
        let inner_num_pis = inner_data.common.num_public_inputs;

        // Build the wrapper with ZK config
        let wrapper_config = CircuitConfig::standard_recursion_polyfri_zk_config();
        let wrapper = ZkWrapperCircuit::new(wrapper_config, inner_data.common);
        let wrapper_data = wrapper.build_circuit();

        // Wrapper should have same number of public inputs as inner
        assert_eq!(wrapper_data.common.num_public_inputs, inner_num_pis);

        // Note: ZK property is enabled via standard_recursion_polyfri_zk_config()
        // which uses FRI ZK hiding. The config struct doesn't expose this directly.
    }
}
