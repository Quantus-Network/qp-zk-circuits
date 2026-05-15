//! Layer-1 aggregation prover (prebuilt-circuit proving API).
//!
//! The layer-0 verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.
//!
//! # Dummy Proof Padding
//!
//! The prover supports padding with dummy L0 proofs when fewer than `num_layer0_proofs`
//! real proofs are provided. Dummy L0 proofs have `block_hash == [0,0,0,0]` and contribute
//! zero-valued exit slots and nullifiers to the aggregated output.

use anyhow::{anyhow, bail, Context, Result};
#[cfg(feature = "std")]
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use qp_wormhole_inputs::BytesDigest;

#[cfg(feature = "std")]
use std::{fs, path::Path};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::bytes_to_digest,
};

use crate::{
    common::utils::{is_dummy_l0_proof, load_verifier_data_from_bytes},
    layer1::{
        circuit::circuit_logic::{Layer1AggregationCircuit, Layer1AggregationCircuitTargets},
        prover::witness::fill_layer1_aggregation_witness,
    },
};

#[derive(Debug)]
pub struct Layer1AggregationInputs {
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub aggregator_address: BytesDigest,
}

#[derive(Debug)]
pub struct Layer1AggregationProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<Layer1AggregationCircuitTargets>,
    num_layer0_proofs: usize,
    layer0_num_leaves: usize,
    dummy_l0_proof_template: ProofWithPublicInputs<F, C, D>,
}

impl Layer1AggregationProver {
    /// Build a fresh layer-1 aggregation prover from circuit definitions.
    ///
    /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        layer1_circuit_config: CircuitConfig,
        layer0_common: CommonCircuitData<F, D>,
        layer0_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_layer0_proofs: usize,
        layer0_num_leaves: usize,
        dummy_l0_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let l1_circuit = Layer1AggregationCircuit::new(
            layer1_circuit_config,
            layer0_common,
            layer0_verifier_only,
            num_layer0_proofs,
            layer0_num_leaves,
        );

        let targets = Some(l1_circuit.targets());
        let circuit_data = l1_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            num_layer0_proofs,
            layer0_num_leaves,
            dummy_l0_proof_template,
        }
    }

    /// Create a layer-1 prover from serialized bytes.
    ///
    /// The `dummy_l0_proof_bytes` should be a serialized L0 aggregated proof created by
    /// aggregating only dummy leaf proofs.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_bytes(
        layer1_prover_only_bytes: &[u8],
        layer1_common_bytes: &[u8],
        layer0_common_bytes: &[u8],
        layer0_verifier_only_bytes: &[u8],
        dummy_l0_proof_bytes: &[u8],
        config: (usize, usize), // (num_leaf_proofs, num_layer0_proofs)
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        let l1_common =
            CommonCircuitData::from_bytes(layer1_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize layer1 common data: {}", e))?;

        let l1_prover_only = ProverOnlyCircuitData::from_bytes(
            layer1_prover_only_bytes,
            &generator_serializer,
            &l1_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize layer1 prover data: {}", e))?;

        let layer0_verifier_data = load_verifier_data_from_bytes(
            layer0_common_bytes,
            layer0_verifier_only_bytes,
            "layer0",
        )?;

        let (num_leaf_proofs, num_layer0_proofs) = config;

        let circuit = Layer1AggregationCircuit::new(
            l1_common.config.clone(),
            layer0_verifier_data.common.clone(),
            &layer0_verifier_data.verifier_only,
            num_layer0_proofs,
            num_leaf_proofs,
        );

        let targets = Some(circuit.targets());

        // Load the dummy L0 proof template
        let dummy_l0_proof_template = ProofWithPublicInputs::<F, C, D>::from_bytes(
            dummy_l0_proof_bytes.to_vec(),
            &layer0_verifier_data.common,
        )
        .map_err(|e| anyhow!("Failed to deserialize dummy L0 proof: {}", e))?;

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: l1_prover_only,
                common: l1_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            num_layer0_proofs,
            layer0_num_leaves: num_leaf_proofs,
            dummy_l0_proof_template,
        })
    }

    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        layer1_prover_path: &Path,
        layer1_common_path: &Path,
        layer0_common_path: &Path,
        layer0_verifier_path: &Path,
        dummy_l0_proof_path: &Path,
        config: (usize, usize),
    ) -> Result<Self> {
        let layer1_prover_only_bytes = fs::read(layer1_prover_path)
            .with_context(|| format!("Failed to read {:?}", layer1_prover_path))?;
        let layer1_common_bytes = fs::read(layer1_common_path)
            .with_context(|| format!("Failed to read {:?}", layer1_common_path))?;

        let layer0_common_bytes = fs::read(layer0_common_path)
            .with_context(|| format!("Failed to read {:?}", layer0_common_path))?;
        let layer0_verifier_only_bytes = fs::read(layer0_verifier_path)
            .with_context(|| format!("Failed to read {:?}", layer0_verifier_path))?;
        let dummy_l0_proof_bytes = fs::read(dummy_l0_proof_path)
            .with_context(|| format!("Failed to read {:?}", dummy_l0_proof_path))?;

        Self::new_from_bytes(
            &layer1_prover_only_bytes,
            &layer1_common_bytes,
            &layer0_common_bytes,
            &layer0_verifier_only_bytes,
            &dummy_l0_proof_bytes,
            config,
        )
    }

    /// Convenience constructor from a generated binaries directory.
    ///
    /// Expected files:
    /// - `layer1_prover.bin`
    /// - `layer1_common.bin`
    /// - `aggregated_common.bin`      (layer-0 common)
    /// - `aggregated_verifier.bin`    (layer-0 verifier-only)
    /// - `dummy_l0_proof.bin`         (dummy L0 aggregated proof for padding)
    /// - `config.json`
    ///
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)?;

        let num_layer0_proofs = bins_config.num_layer0_proofs.ok_or_else(|| {
            anyhow!(
                "config is missing num_layer0_proofs. Regenerate binaries with num_layer0_proofs set."
            )
        })?;
        let config = (bins_config.num_leaf_proofs, num_layer0_proofs);

        Self::new_from_files(
            &bins_dir.join("layer1_prover.bin"),
            &bins_dir.join("layer1_common.bin"),
            &bins_dir.join("aggregated_common.bin"),
            &bins_dir.join("aggregated_verifier.bin"),
            &bins_dir.join("dummy_l0_proof.bin"),
            config,
        )
    }

    pub fn num_layer0_proofs(&self) -> usize {
        self.num_layer0_proofs
    }

    pub fn layer0_num_leaves(&self) -> usize {
        self.layer0_num_leaves
    }

    /// Commit layer-0 aggregated proofs into the layer-1 circuit witness.
    ///
    /// Supports padding with dummy L0 proofs when fewer than `num_layer0_proofs` are provided.
    /// The prover ensures a real proof is in slot 0 if any real proofs exist (required for
    /// correct reference value extraction in the circuit).
    pub fn commit(mut self, inputs: Layer1AggregationInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("layer-1 aggregation prover has already committed to inputs");
        };

        let mut proofs = inputs.proofs;
        let aggregator_address = inputs.aggregator_address;

        if proofs.len() > self.num_layer0_proofs {
            bail!(
                "too many L0 proofs: got {}, expected at most {}",
                proofs.len(),
                self.num_layer0_proofs
            );
        }

        // Pad with dummy L0 proofs
        let num_dummies_needed = self.num_layer0_proofs.saturating_sub(proofs.len());
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_l0_proof_template.clone());
        }

        // Ensure a real proof is in slot 0 (if any real proofs exist)
        // The circuit derives reference values from slot 0.
        if let Some(first_real_idx) = proofs
            .iter()
            .position(|p| !is_dummy_l0_proof(p, self.layer0_num_leaves).unwrap_or(false))
        {
            proofs.swap(0, first_real_idx);
        }

        let aggregator_address_felts = bytes_to_digest(aggregator_address);

        fill_layer1_aggregation_witness(
            &mut self.partial_witness,
            &targets,
            &proofs,
            aggregator_address_felts,
        )?;

        Ok(self)
    }

    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove layer-1 aggregation circuit: {}", e))
    }
}
