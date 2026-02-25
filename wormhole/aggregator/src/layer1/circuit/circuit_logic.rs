//! Layer-1 aggregation circuit (monolithic prebuilt-circuit form).
//!
//! Verifies N layer-0 aggregated proofs directly and emits a layer-1 aggregated proof.

use anyhow::{anyhow, Result};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, ProverCircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::gadgets::bytes_digest_eq;

use super::constants as l1c;

/// Runtime targets needed to fill witnesses for the prebuilt layer-1 circuit.
#[derive(Debug, Clone)]
pub struct Layer1AggregationCircuitTargets {
    pub layer0_verifier_data: VerifierCircuitTarget,
    pub layer0_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// Aggregator address is now a witness target (4 felts / 32 bytes), not a circuit constant.
    pub aggregator_address: HashOutTarget,
}

/// Monolithic layer-1 aggregation circuit builder.
#[derive(Debug, Clone)]
pub struct Layer1AggregationCircuit {
    /// Circuit config for the layer-1 aggregation circuit itself.
    pub config: CircuitConfig,
    /// Common data for the child (layer-0) proof circuit.
    pub layer0_common: CommonCircuitData<F, D>,
    /// Number of layer-0 proofs aggregated by this layer-1 circuit.
    pub num_layer0_proofs: usize,
    /// Number of leaf proofs represented in each layer-0 proof (used to parse l0 PI layout).
    pub layer0_num_leaves: usize,
}

impl Layer1AggregationCircuit {
    pub fn new(
        config: CircuitConfig,
        layer0_common: CommonCircuitData<F, D>,
        num_layer0_proofs: usize,
        layer0_num_leaves: usize,
    ) -> Self {
        Self {
            config,
            layer0_common,
            num_layer0_proofs,
            layer0_num_leaves,
        }
    }

    pub fn targets(&self) -> Layer1AggregationCircuitTargets {
        let (_, targets) = self
            .build_internal()
            .expect("failed to build layer1 circuit");
        targets
    }

    pub fn build_prover(&self) -> ProverCircuitData<F, C, D> {
        let (cd, _) = self
            .build_internal()
            .expect("failed to build layer1 prover");
        ProverCircuitData {
            prover_only: cd.prover_only,
            common: cd.common,
        }
    }

    pub fn build_verifier(&self) -> VerifierCircuitData<F, C, D> {
        let (cd, _) = self
            .build_internal()
            .expect("failed to build layer1 verifier");
        VerifierCircuitData {
            verifier_only: cd.verifier_only,
            common: cd.common,
        }
    }

    fn build_internal(
        &self,
    ) -> Result<(
        plonky2::plonk::circuit_data::CircuitData<F, C, D>,
        Layer1AggregationCircuitTargets,
    )> {
        if self.num_layer0_proofs == 0 {
            return Err(anyhow!("num_layer0_proofs must be > 0"));
        }

        let l0_pi_len = l1c::l0_pi_len(self.layer0_num_leaves);
        let l0_exit_slots_per_proof = l1c::l0_exit_slots_count(self.layer0_num_leaves);
        let l0_nullifiers_per_proof = l1c::l0_nullifiers_count(self.layer0_num_leaves);

        let mut builder = CircuitBuilder::<F, D>::new(self.config.clone());

        // Shared verifier data target for all child proofs (layer-0 proofs)
        let layer0_verifier_data =
            builder.add_virtual_verifier_data(self.layer0_common.fri_params.config.cap_height);

        // Add and verify all child proofs
        let mut layer0_proofs = Vec::with_capacity(self.num_layer0_proofs);
        for _ in 0..self.num_layer0_proofs {
            let pt = builder.add_virtual_proof_with_pis(&self.layer0_common);
            builder.verify_proof::<C>(&pt, &layer0_verifier_data, &self.layer0_common);
            layer0_proofs.push(pt);
        }

        // NEW: aggregator address is a virtual target (witness-filled)
        let aggregator_address = builder.add_virtual_hash();

        let zero = builder.zero();
        let one = builder.one();

        // Build output PIs
        let mut output_pis: Vec<Target> = Vec::new();

        // 1) Aggregator address (witness target, not constant)
        output_pis.extend_from_slice(aggregator_address.elements.as_ref());

        // 2) Reference values from proof 0
        let proof0_pis = &layer0_proofs[0].public_inputs;

        // Sanity check expected child PI length (best-effort: runtime proof target length is fixed by common)
        if proof0_pis.len() != self.layer0_common.num_public_inputs {
            return Err(anyhow!(
                "layer0 proof PI target len {} != layer0 common num_public_inputs {}",
                proof0_pis.len(),
                self.layer0_common.num_public_inputs
            ));
        }

        // Optional check against computed expected layout
        // (This catches a config mismatch: wrong layer0_num_leaves passed here.)
        if self.layer0_common.num_public_inputs != l0_pi_len {
            return Err(anyhow!(
                "layer0 common PI length {} != expected layer0 PI length {} (layer0_num_leaves={})",
                self.layer0_common.num_public_inputs,
                l0_pi_len,
                self.layer0_num_leaves
            ));
        }

        let asset_ref = proof0_pis[l1c::L0_ASSET_ID_OFFSET];
        let fee_ref = proof0_pis[l1c::L0_VOLUME_FEE_BPS_OFFSET];
        output_pis.push(asset_ref);
        output_pis.push(fee_ref);

        let block_ref: [Target; 4] =
            core::array::from_fn(|j| proof0_pis[l1c::L0_BLOCK_HASH_OFFSET + j]);
        let block_number_ref = proof0_pis[l1c::L0_BLOCK_NUMBER_OFFSET];

        let dummy_block = [zero; 4];

        // 3) Enforce all child proofs share asset/fee and block hash (or are dummies)
        for proof_t in &layer0_proofs {
            let child_pis = &proof_t.public_inputs;

            // asset_id and volume_fee_bps must match
            builder.connect(child_pis[l1c::L0_ASSET_ID_OFFSET], asset_ref);
            builder.connect(child_pis[l1c::L0_VOLUME_FEE_BPS_OFFSET], fee_ref);

            // Dummy sentinel for layer-0 proof: block_hash == [0,0,0,0]
            let child_block: [Target; 4] =
                core::array::from_fn(|j| child_pis[l1c::L0_BLOCK_HASH_OFFSET + j]);

            let is_dummy = bytes_digest_eq(&mut builder, child_block, dummy_block);
            let matches_ref = bytes_digest_eq(&mut builder, child_block, block_ref);
            let ok = builder.or(is_dummy, matches_ref);

            builder.connect(ok.target, one);
        }

        output_pis.extend_from_slice(&block_ref);
        output_pis.push(block_number_ref);

        // 4) Total exit slots
        let total_exit_slots = self.num_layer0_proofs * l0_exit_slots_per_proof;
        output_pis.push(builder.constant(F::from_canonical_usize(total_exit_slots)));

        // 5) Forward exit slots from all layer-0 proofs
        let exit_slots_start = l1c::l0_exit_slots_start();
        for proof_t in &layer0_proofs {
            let child_pis = &proof_t.public_inputs;
            for slot_idx in 0..l0_exit_slots_per_proof {
                let slot_base = exit_slots_start + slot_idx * l1c::L0_EXIT_SLOT_LEN;
                for j in 0..l1c::L0_EXIT_SLOT_LEN {
                    output_pis.push(child_pis[slot_base + j]);
                }
            }
        }

        // 6) Forward nullifiers from all layer-0 proofs
        let nullifiers_start = l1c::l0_nullifiers_start(self.layer0_num_leaves);
        for proof_t in &layer0_proofs {
            let child_pis = &proof_t.public_inputs;
            for n_idx in 0..l0_nullifiers_per_proof {
                let base = nullifiers_start + n_idx * 4;
                for j in 0..4 {
                    output_pis.push(child_pis[base + j]);
                }
            }
        }

        builder.register_public_inputs(&output_pis);

        let cd = builder.build::<C>();

        Ok((
            cd,
            Layer1AggregationCircuitTargets {
                layer0_verifier_data,
                layer0_proofs,
                aggregator_address,
            },
        ))
    }
}
