//! Private-batch aggregation prover (prebuilt-circuit proving API).
//!
//! - `new(...)` / `new_from_*` constructors
//! - `commit(...)` to fill the witness
//! - `prove()` to generate the aggregated proof
//!
//! The leaf verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.

use anyhow::{anyhow, bail, Context, Result};
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
use rand::seq::SliceRandom;

#[cfg(feature = "std")]
use std::{fs, path::Path};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::bytes_to_digest,
};

use crate::{
    common::utils::{
        ensure_proof_public_input_len, leaf_proof_asset_id, load_verifier_data_from_bytes,
    },
    dummy_proof::{generate_random_nullifier_preimage, load_dummy_proof},
    private_batch::{
        circuit::circuit_logic::{PrivateBatchCircuitTargets, PrivateBatchCircuit},
        prover::witness::fill_private_batch_witness,
    },
};

#[derive(Debug)]
pub struct PrivateBatchProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<PrivateBatchCircuitTargets>,
    num_leaf_proofs: usize,
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
}

impl PrivateBatchProver {
    /// Build a fresh private-batch aggregation prover from circuit definitions.
    ///
    /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
    pub fn new(
        agg_circuit_config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_leaf_proofs: usize,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let agg_circuit = PrivateBatchCircuit::new(
            agg_circuit_config,
            &leaf_common,
            leaf_verifier_only,
            num_leaf_proofs,
        );

        let targets = Some(agg_circuit.targets());
        let circuit_data = agg_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            num_leaf_proofs,
            dummy_proof_template,
        }
    }

    /// Create a private-batch aggregation prover from serialized bytes.
    ///
    /// Expected bytes:
    /// - `aggregated_prover_only_bytes`: private-batch aggregated prover-only circuit data
    /// - `aggregated_common_bytes`: private-batch aggregated common circuit data
    /// - `leaf_common_bytes`: leaf circuit common data (`common.bin`)
    /// - `leaf_verifier_only_bytes`: leaf verifier-only data (`verifier.bin`)
    /// - `dummy_proof_bytes`: serialized dummy leaf proof (`dummy_proof.bin`)
    /// - `num_leaf_proofs`: number of leaf proofs aggregated by this private-batch prover
    pub fn new_from_bytes(
        aggregated_prover_only_bytes: &[u8],
        aggregated_common_bytes: &[u8],
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
        num_leaf_proofs: usize,
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        // 1) Load prebuilt aggregation circuit prover data
        let agg_common =
            CommonCircuitData::from_bytes(aggregated_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("failed to deserialize aggregated common data: {}", e))?;

        let agg_prover_only = ProverOnlyCircuitData::from_bytes(
            aggregated_prover_only_bytes,
            &generator_serializer,
            &agg_common,
        )
        .map_err(|e| anyhow!("failed to deserialize aggregated prover data: {}", e))?;

        // 2) Load leaf verifier data (needed to reconstruct targets + parse dummy proof)
        let leaf_verifier_data =
            load_verifier_data_from_bytes(leaf_common_bytes, leaf_verifier_only_bytes, "leaf")?;

        // 3) Reconstruct the aggregation circuit to get targets.
        // NOTE: This builds a fresh circuit to extract target structure. The verifier key
        // must match what was used when the prebuilt binaries were created.
        let circuit = PrivateBatchCircuit::new(
            agg_common.config.clone(),
            &leaf_verifier_data.common,
            &leaf_verifier_data.verifier_only,
            num_leaf_proofs,
        );

        let targets = Some(circuit.targets());

        // 4) Load dummy proof template compatible with the leaf verifier common data
        let dummy_proof_template =
            load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                .map_err(|e| anyhow!("failed to deserialize dummy proof: {}", e))?;

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: agg_prover_only,
                common: agg_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            num_leaf_proofs,
            dummy_proof_template,
        })
    }

    /// Create a private-batch aggregation prover from explicit file paths.
    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        aggregated_prover_path: &Path,
        aggregated_common_path: &Path,
        leaf_common_path: &Path,
        leaf_verifier_path: &Path,
        dummy_proof_path: &Path,
        num_leaf_proofs: usize,
    ) -> Result<Self> {
        let aggregated_prover_only_bytes = fs::read(aggregated_prover_path).with_context(|| {
            format!(
                "Failed to read aggregated prover file {:?}",
                aggregated_prover_path
            )
        })?;
        let aggregated_common_bytes = fs::read(aggregated_common_path).with_context(|| {
            format!(
                "Failed to read aggregated common file {:?}",
                aggregated_common_path
            )
        })?;
        let leaf_common_bytes = fs::read(leaf_common_path)
            .with_context(|| format!("Failed to read leaf common file {:?}", leaf_common_path))?;
        let leaf_verifier_only_bytes = fs::read(leaf_verifier_path).with_context(|| {
            format!("Failed to read leaf verifier file {:?}", leaf_verifier_path)
        })?;
        let dummy_proof_bytes = fs::read(dummy_proof_path)
            .with_context(|| format!("Failed to read dummy proof file {:?}", dummy_proof_path))?;

        Self::new_from_bytes(
            &aggregated_prover_only_bytes,
            &aggregated_common_bytes,
            &leaf_common_bytes,
            &leaf_verifier_only_bytes,
            &dummy_proof_bytes,
            num_leaf_proofs,
        )
    }

    /// Convenience constructor that loads everything from a generated binaries directory.
    ///
    /// Expected files:
    /// - `private_batch_prover.bin`
    /// - `private_batch_common.bin`
    /// - `common.bin`
    /// - `verifier.bin`
    /// - `dummy_proof.bin`
    /// - `config.json`
    ///
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)
            .with_context(|| format!("Failed to load config.json from {}", bins_dir.display()))?;
        let num_leaf_proofs = bins_config.num_leaf_proofs;

        Self::new_from_files(
            &bins_dir.join("private_batch_prover.bin"),
            &bins_dir.join("private_batch_common.bin"),
            &bins_dir.join("common.bin"),
            &bins_dir.join("verifier.bin"),
            &bins_dir.join("dummy_proof.bin"),
            num_leaf_proofs,
        )
    }

    // -------------------------------------------------------------------------
    // Proving API
    // -------------------------------------------------------------------------

    /// Number of leaf proofs aggregated by this private-batch prover.
    pub fn num_leaf_proofs(&self) -> usize {
        self.num_leaf_proofs
    }

    /// Commit leaf proofs to the aggregation circuit witness.
    ///
    /// Performs padding with dummy proofs, shuffling, and witness filling.
    pub fn commit(mut self, mut proofs: Vec<ProofWithPublicInputs<F, C, D>>) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("private-batch aggregation prover has already committed to inputs");
        };

        if proofs.len() > self.num_leaf_proofs {
            bail!(
                "too many proofs: got {}, expected at most {}",
                proofs.len(),
                self.num_leaf_proofs
            );
        }

        // If we're going to pad with dummy proofs (asset_id = 0), ensure real proofs are asset_id=0.
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            assert_dummy_padding_asset_id_compatible(&proofs)?;
        }

        // Pad with dummy proofs
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }

        // Uniformly shuffle proofs to hide dummy positions. The circuit selects its block
        // reference from the first non-dummy slot in-circuit, so no position is special.
        if proofs.len() > 1 {
            let mut rng = rand::thread_rng();
            proofs.shuffle(&mut rng);
        }

        // Generate one dummy nullifier preimage per slot.
        // In-circuit hashes these only for dummy proofs.
        let dummy_nullifier_pre_images =
            generate_dummy_nullifier_pre_images_for_slots(proofs.len());

        fill_private_batch_witness(
            &mut self.partial_witness,
            &targets,
            &proofs,
            &dummy_nullifier_pre_images,
        )?;

        Ok(self)
    }

    /// Generate the aggregated private-batch proof after `commit(...)`.
    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove private-batch aggregation circuit: {}", e))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// If we're padding with dummy proofs (`asset_id = 0`), real proofs must also use `asset_id = 0`
/// because the private-batch circuit enforces asset_id equality across all proofs.
fn assert_dummy_padding_asset_id_compatible(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    for (idx, proof) in proofs.iter().enumerate() {
        ensure_proof_public_input_len(
            proof,
            crate::private_batch::circuit::constants::LEAF_PI_LEN,
            "leaf proof",
        )?;
        let real_asset_id = leaf_proof_asset_id(proof)?;

        if real_asset_id != 0 {
            bail!(
                "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                 All proofs must have the same asset_id for aggregation when padding is required.",
                idx,
                real_asset_id
            );
        }
    }

    Ok(())
}

/// Generate a dummy nullifier preimage for every slot.
///
/// The private-batch circuit hashes these for dummy slots (`block_hash == 0`) and ignores them
/// for real slots via conditional select.
fn generate_dummy_nullifier_pre_images_for_slots(n_slots: usize) -> Vec<[F; 4]> {
    (0..n_slots)
        .map(|_| bytes_to_digest(generate_random_nullifier_preimage()))
        .collect()
}
