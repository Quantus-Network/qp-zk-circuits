use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use wormhole_circuit::{
    circuit::{CircuitFragment, C, D, F},
    gadgets::is_const_less_than,
};
use wormhole_verifier::WormholeVerifier;

use crate::MAX_NUM_PROOFS_TO_AGGREGATE;

#[derive(Debug, Clone)]
pub struct WormholeProofAggregatorTargets {
    verifier_data: VerifierCircuitTarget,
    proofs: [ProofWithPublicInputsTarget<D>; MAX_NUM_PROOFS_TO_AGGREGATE],
    num_proofs: Target,
    // HACK: This allows us to only create `circuit_data` once.
    circuit_data: CommonCircuitData<F, D>,
}

impl WormholeProofAggregatorTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>, zk: bool) -> Self {
        let circuit_data = WormholeVerifier::new(zk, None).circuit_data.common;
        let verifier_data =
            builder.add_virtual_verifier_data(circuit_data.fri_params.config.cap_height);

        // Setup targets for proofs.
        let num_proofs = builder.add_virtual_target();
        let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
            proofs.push(builder.add_virtual_proof_with_pis(&circuit_data));
        }

        let proofs: [ProofWithPublicInputsTarget<D>; MAX_NUM_PROOFS_TO_AGGREGATE] =
            std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&circuit_data));

        Self {
            verifier_data,
            proofs,
            num_proofs,
            circuit_data,
        }
    }
}

pub struct WormholeProofAggregatorInputs {
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    num_proofs: usize,
}

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    inner_verifier: WormholeVerifier,
}

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        let inner_verifier = WormholeVerifier::new(false, None);
        Self { inner_verifier }
    }
}

impl WormholeProofAggregator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CircuitFragment for WormholeProofAggregator {
    type PrivateInputs = WormholeProofAggregatorInputs;
    type Targets = WormholeProofAggregatorTargets;

    fn circuit(
        &Self::Targets {
            ref verifier_data,
            ref proofs,
            num_proofs,
            ref circuit_data,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Verify each aggregated proof separately.
        let n_log = (usize::BITS - (MAX_NUM_PROOFS_TO_AGGREGATE - 1).leading_zeros()) as usize;
        for (i, proof) in proofs.iter().enumerate() {
            let is_proof = is_const_less_than(builder, i, num_proofs, n_log);
            builder
                .conditionally_verify_proof_or_dummy::<C>(
                    is_proof,
                    proof,
                    verifier_data,
                    circuit_data,
                )
                .unwrap();
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_target(
            targets.num_proofs,
            F::from_canonical_usize(inputs.num_proofs),
        )?;
        for (proof_target, proof) in targets.proofs.iter().zip(inputs.proofs.iter()) {
            pw.set_proof_with_pis_target(proof_target, proof)?;
        }

        pw.set_verifier_data_target(
            &targets.verifier_data,
            &self.inner_verifier.circuit_data.verifier_only,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hashbrown::HashMap;
    use plonky2::recursion::dummy_circuit::dummy_circuit;
    use plonky2::recursion::dummy_circuit::dummy_proof;
    use wormhole_circuit::circuit::tests::{build_and_prove_test, setup_test_builder_and_witness};
    use wormhole_circuit::inputs::CircuitInputs;
    use wormhole_prover::WormholeProver;

    fn run_test(
        inputs: WormholeProofAggregatorInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness(false);
        let targets = WormholeProofAggregatorTargets::new(&mut builder, false);
        WormholeProofAggregator::circuit(&targets, &mut builder);

        let aggregator = WormholeProofAggregator::new();
        aggregator.fill_targets(&mut pw, targets, inputs)?;
        build_and_prove_test(builder, pw)
    }

    #[ignore = "takes too long"]
    #[test]
    fn build_and_verify_proof() {
        // Create proofs.
        let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
            let prover = WormholeProver::new(false);
            let inputs = CircuitInputs::test_inputs();
            let proof = prover.commit(&inputs).unwrap().prove().unwrap();
            proofs.push(proof);
        }

        let num_proofs = proofs.len();
        let inputs = WormholeProofAggregatorInputs { proofs, num_proofs };
        run_test(inputs).unwrap();
    }

    #[ignore = "takes too long"]
    #[test]
    fn few_proofs_pass() {
        // Create proofs.
        let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
        let mut dummy_proofs = Vec::new();
        for i in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
            let prover = WormholeProver::new(false);
            if i < MAX_NUM_PROOFS_TO_AGGREGATE / 2 {
                let inputs = CircuitInputs::test_inputs();
                let proof = prover.commit(&inputs).unwrap().prove().unwrap();
                proofs.push(proof);
            } else {
                let dummy_circuit = dummy_circuit(&prover.circuit_data.common);
                let dummy_proof = dummy_proof(&dummy_circuit, HashMap::new()).unwrap();
                dummy_proofs.push(dummy_proof);
            }
        }

        // Get the number of valid proofs before appending the dummy proofs.
        let num_proofs = proofs.len();
        proofs.extend_from_slice(&dummy_proofs);

        let inputs = WormholeProofAggregatorInputs { proofs, num_proofs };
        run_test(inputs).unwrap();
    }
}
