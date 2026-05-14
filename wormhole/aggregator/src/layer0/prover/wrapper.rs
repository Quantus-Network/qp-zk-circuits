//! Combined Layer-0 prover with ZK wrapper optimization.
//!
//! This prover uses a two-step approach for ~1.8x speedup:
//! 1. Non-ZK L0 aggregation (fast)
//! 2. ZK wrapper (adds ZK property)

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_data::{
            CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData, VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};

#[cfg(feature = "std")]
use std::{fs, path::Path};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::bytes_to_digest,
};

use crate::{
    common::utils::{
        assert_dummy_padding_asset_id_compatible, load_verifier_data_from_bytes,
        shuffle_proofs_preserving_first_real,
    },
    dummy_proof::{generate_random_nullifier_preimage, load_dummy_proof},
    layer0::{
        circuit::circuit_logic::{AggregationCircuitTargets, Layer0AggregationCircuit},
        prover::witness::fill_layer0_aggregation_witness,
    },
    zk_wrapper::circuit::{ZkWrapperCircuit, ZkWrapperTargets},
};

/// Layer-0 aggregation prover with ZK wrapper optimization.
///
/// Uses a two-step proving process:
/// 1. Non-ZK L0 aggregation (~3.7s for 16 proofs)
/// 2. ZK wrapper (~1s)
///
/// Total: ~4.8s vs ~8.8s for direct ZK (~1.8x speedup)
pub struct Layer0WrapperProver {
    /// Non-ZK L0 prover circuit data
    nonzk_circuit_data: ProverCircuitData<F, C, D>,
    /// Non-ZK L0 verifier-only data (for the wrapper)
    nonzk_verifier_only: VerifierOnlyCircuitData<C, D>,
    /// ZK wrapper prover circuit data
    wrapper_circuit_data: ProverCircuitData<F, C, D>,
    /// ZK wrapper targets
    wrapper_targets: ZkWrapperTargets,
    /// Witness for non-ZK L0 (filled during commit)
    nonzk_partial_witness: PartialWitness<F>,
    /// Non-ZK L0 targets (consumed on commit)
    nonzk_targets: Option<AggregationCircuitTargets>,
    /// Leaf verifier-only data
    leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
    /// Number of leaf proofs
    num_leaf_proofs: usize,
    /// Dummy proof template
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
}

impl Layer0WrapperProver {
    // -------------------------------------------------------------------------
    // Constructors (bytes / files)
    // -------------------------------------------------------------------------

    /// Create from serialized bytes.
    pub fn new_from_bytes(
        nonzk_prover_only_bytes: &[u8],
        nonzk_common_bytes: &[u8],
        nonzk_verifier_only_bytes: &[u8],
        wrapper_prover_only_bytes: &[u8],
        wrapper_common_bytes: &[u8],
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
        num_leaf_proofs: usize,
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        // Load non-ZK L0 circuit data
        let nonzk_common =
            CommonCircuitData::from_bytes(nonzk_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize non-ZK common data: {}", e))?;

        let nonzk_prover_only = ProverOnlyCircuitData::from_bytes(
            nonzk_prover_only_bytes,
            &generator_serializer,
            &nonzk_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize non-ZK prover data: {}", e))?;

        let nonzk_verifier_only =
            VerifierOnlyCircuitData::<C, D>::from_bytes(nonzk_verifier_only_bytes.to_vec())
                .map_err(|e| anyhow!("Failed to deserialize non-ZK verifier data: {}", e))?;

        // Load ZK wrapper circuit data
        let wrapper_common =
            CommonCircuitData::from_bytes(wrapper_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize wrapper common data: {}", e))?;

        let wrapper_prover_only = ProverOnlyCircuitData::from_bytes(
            wrapper_prover_only_bytes,
            &generator_serializer,
            &wrapper_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize wrapper prover data: {}", e))?;

        // Load leaf verifier data
        let leaf_verifier_data =
            load_verifier_data_from_bytes(leaf_common_bytes, leaf_verifier_only_bytes, "leaf")?;

        // Reconstruct non-ZK L0 targets
        let nonzk_config = nonzk_common.config.clone();
        let nonzk_circuit = Layer0AggregationCircuit::new(
            nonzk_config,
            leaf_verifier_data.common.clone(),
            num_leaf_proofs,
        );
        let nonzk_targets = Some(nonzk_circuit.targets());

        // Reconstruct wrapper targets
        let wrapper_config = wrapper_common.config.clone();
        let wrapper_circuit = ZkWrapperCircuit::new(wrapper_config, nonzk_common.clone());
        let wrapper_targets = wrapper_circuit.targets();

        // Load dummy proof
        let dummy_proof_template =
            load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                .map_err(|e| anyhow!("Failed to deserialize dummy proof: {}", e))?;

        Ok(Self {
            nonzk_circuit_data: ProverCircuitData {
                prover_only: nonzk_prover_only,
                common: nonzk_common,
            },
            nonzk_verifier_only,
            wrapper_circuit_data: ProverCircuitData {
                prover_only: wrapper_prover_only,
                common: wrapper_common,
            },
            wrapper_targets,
            nonzk_partial_witness: PartialWitness::new(),
            nonzk_targets,
            leaf_verifier_only: leaf_verifier_data.verifier_only,
            num_leaf_proofs,
            dummy_proof_template,
        })
    }

    /// Load from binaries directory.
    ///
    /// Expected files:
    /// - `aggregated_nonzk_prover.bin`
    /// - `aggregated_nonzk_common.bin`
    /// - `aggregated_nonzk_verifier.bin`
    /// - `wrapper_prover.bin`
    /// - `wrapper_common.bin`
    /// - `common.bin` (leaf)
    /// - `verifier.bin` (leaf)
    /// - `dummy_proof.bin`
    /// - `config.json`
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)
            .with_context(|| format!("Failed to load config.json from {}", bins_dir.display()))?;
        let num_leaf_proofs = bins_config.num_leaf_proofs;

        let nonzk_prover_bytes = fs::read(bins_dir.join("aggregated_nonzk_prover.bin"))
            .with_context(|| "Failed to read aggregated_nonzk_prover.bin")?;
        let nonzk_common_bytes = fs::read(bins_dir.join("aggregated_nonzk_common.bin"))
            .with_context(|| "Failed to read aggregated_nonzk_common.bin")?;
        let nonzk_verifier_bytes = fs::read(bins_dir.join("aggregated_nonzk_verifier.bin"))
            .with_context(|| "Failed to read aggregated_nonzk_verifier.bin")?;
        let wrapper_prover_bytes = fs::read(bins_dir.join("wrapper_prover.bin"))
            .with_context(|| "Failed to read wrapper_prover.bin")?;
        let wrapper_common_bytes = fs::read(bins_dir.join("wrapper_common.bin"))
            .with_context(|| "Failed to read wrapper_common.bin")?;
        let leaf_common_bytes =
            fs::read(bins_dir.join("common.bin")).with_context(|| "Failed to read common.bin")?;
        let leaf_verifier_bytes = fs::read(bins_dir.join("verifier.bin"))
            .with_context(|| "Failed to read verifier.bin")?;
        let dummy_proof_bytes = fs::read(bins_dir.join("dummy_proof.bin"))
            .with_context(|| "Failed to read dummy_proof.bin")?;

        Self::new_from_bytes(
            &nonzk_prover_bytes,
            &nonzk_common_bytes,
            &nonzk_verifier_bytes,
            &wrapper_prover_bytes,
            &wrapper_common_bytes,
            &leaf_common_bytes,
            &leaf_verifier_bytes,
            &dummy_proof_bytes,
            num_leaf_proofs,
        )
    }

    // -------------------------------------------------------------------------
    // Proving API
    // -------------------------------------------------------------------------

    /// Number of leaf proofs aggregated.
    pub fn num_leaf_proofs(&self) -> usize {
        self.num_leaf_proofs
    }

    /// Commit leaf proofs to be aggregated.
    pub fn commit(mut self, mut proofs: Vec<ProofWithPublicInputs<F, C, D>>) -> Result<Self> {
        let Some(targets) = self.nonzk_targets.take() else {
            bail!("prover has already committed to inputs");
        };

        if proofs.len() > self.num_leaf_proofs {
            bail!(
                "too many proofs: got {}, expected at most {}",
                proofs.len(),
                self.num_leaf_proofs
            );
        }

        // Pad with dummy proofs if needed
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            assert_dummy_padding_asset_id_compatible(&proofs)?;
        }

        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }

        // Shuffle proofs
        shuffle_proofs_preserving_first_real(&mut proofs);

        // Generate dummy nullifier preimages
        let dummy_nullifier_pre_images: Vec<[F; 4]> = (0..proofs.len())
            .map(|_| bytes_to_digest(generate_random_nullifier_preimage()))
            .collect();

        // Fill non-ZK L0 witness
        fill_layer0_aggregation_witness(
            &mut self.nonzk_partial_witness,
            &targets,
            &self.leaf_verifier_only,
            &proofs,
            &dummy_nullifier_pre_images,
        )?;

        Ok(self)
    }

    /// Generate the ZK-wrapped aggregated proof.
    ///
    /// This performs two proving steps internally:
    /// 1. Non-ZK L0 aggregation
    /// 2. ZK wrapper
    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        // Step 1: Generate non-ZK L0 proof
        let nonzk_proof = self
            .nonzk_circuit_data
            .prove(self.nonzk_partial_witness)
            .map_err(|e| anyhow!("Failed to prove non-ZK L0: {}", e))?;

        // Step 2: Wrap with ZK using prebuilt wrapper circuit
        let mut wrapper_witness = PartialWitness::new();
        wrapper_witness
            .set_verifier_data_target(
                &self.wrapper_targets.inner_verifier_data,
                &self.nonzk_verifier_only,
            )
            .map_err(|e| anyhow!("Failed to set wrapper verifier data: {}", e))?;
        wrapper_witness
            .set_proof_with_pis_target(&self.wrapper_targets.inner_proof, &nonzk_proof)
            .map_err(|e| anyhow!("Failed to set wrapper proof: {}", e))?;

        self.wrapper_circuit_data
            .prove(wrapper_witness)
            .map_err(|e| anyhow!("Failed to prove ZK wrapper: {}", e))
    }
}
