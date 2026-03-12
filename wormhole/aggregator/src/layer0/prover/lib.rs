//! Layer-0 aggregation prover (prebuilt-circuit proving API).
//!
//! This mirrors the `WormholeProver` API style for leaf proofs, but for the
//! monolithic layer-0 aggregation circuit:
//!
//! - `new(...)` / `new_from_*` constructors
//! - `commit(...)` to fill the witness
//! - `prove()` to generate the aggregated proof
//!
//! The prover expects a prebuilt aggregation circuit (prover/common) plus a
//! config.json file (`config.json`) which contains the aggregation config (number of leaf/layer0 proofs) and binary hashes for integrity verification.
use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
            VerifierOnlyCircuitData,
        },
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use rand::seq::SliceRandom;

#[cfg(feature = "std")]
use std::{fs, path::Path};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::digest_bytes_to_felts,
};

use crate::{
    common::utils::load_verifier_data_from_bytes,
    dummy_proof::{generate_random_nullifier, load_dummy_proof},
    layer0::{
        circuit::circuit_logic::{AggregationCircuitTargets, Layer0AggregationCircuit},
        prover::witness::fill_layer0_aggregation_witness,
    },
};

/// Public inputs for the layer-0 aggregation prover.
///
/// We take ownership of proofs to avoid an expensive clone in `commit(...)`.
#[derive(Debug)]
pub struct Layer0AggregationInputs {
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
}

#[derive(Debug)]
pub struct Layer0AggregationProver {
    /// Prebuilt layer-0 aggregation prover circuit data.
    pub circuit_data: ProverCircuitData<F, C, D>,

    /// Witness filled during `commit(...)`.
    partial_witness: PartialWitness<F>,

    /// Runtime targets for the prebuilt aggregation circuit (consumed on commit).
    targets: Option<AggregationCircuitTargets>,

    /// Leaf verifier-only data used to fill `add_virtual_verifier_data(...)` targets.
    leaf_verifier_only: VerifierOnlyCircuitData<C, D>,

    /// Aggregation config (`num_leaf_proofs`).
    num_leaf_proofs: usize,

    /// Dummy leaf proof template for padding.
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
}

impl Layer0AggregationProver {
    // -------------------------------------------------------------------------
    // Constructors (fresh build path)
    // -------------------------------------------------------------------------

    /// Build a fresh layer-0 aggregation prover from circuit definitions.
    ///
    /// This is the "dev/fallback" path. In production, prefer `new_from_binaries_dir(...)`
    /// or `new_from_files(...)` so the aggregation circuit is prebuilt and loaded to reduce overhead.
    pub fn new(
        agg_circuit_config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
        num_leaf_proofs: usize,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let agg_circuit =
            Layer0AggregationCircuit::new(agg_circuit_config, leaf_common, num_leaf_proofs);

        let targets = Some(agg_circuit.targets());
        let circuit_data = agg_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            leaf_verifier_only,
            num_leaf_proofs,
            dummy_proof_template,
        }
    }

    // -------------------------------------------------------------------------
    // Constructors (bytes / files)
    // -------------------------------------------------------------------------

    /// Create a layer-0 aggregation prover from serialized bytes.
    ///
    /// Expected bytes:
    /// - `aggregated_prover_only_bytes`: layer-0 aggregated prover-only circuit data
    /// - `aggregated_common_bytes`: layer-0 aggregated common circuit data
    /// - `leaf_common_bytes`: leaf circuit common data (`common.bin`)
    /// - `leaf_verifier_only_bytes`: leaf verifier-only data (`verifier.bin`)
    /// - `dummy_proof_bytes`: serialized dummy leaf proof (`dummy_proof.bin`)
    /// - `num_leaf_proofs`: number of leaf proofs aggregated by this layer-0 prover
    pub fn new_from_bytes(
        aggregated_prover_only_bytes: &[u8],
        aggregated_common_bytes: &[u8],
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
        num_leaf_proofs: usize,
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
            _phantom: Default::default(),
        };

        // 1) Load prebuilt aggregation circuit prover data
        let agg_common =
            CommonCircuitData::from_bytes(aggregated_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize aggregated common data: {}", e))?;

        let agg_prover_only = ProverOnlyCircuitData::from_bytes(
            aggregated_prover_only_bytes,
            &generator_serializer,
            &agg_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize aggregated prover data: {}", e))?;

        // 2) Load leaf verifier data (needed to set verifier target + parse dummy proof)
        let leaf_verifier_data =
            load_verifier_data_from_bytes(leaf_common_bytes, leaf_verifier_only_bytes, "leaf")?;

        // 3) Reconstruct the aggregation circuit to get targets.
        let circuit = Layer0AggregationCircuit::new(
            agg_common.config.clone(),
            leaf_verifier_data.common.clone(),
            num_leaf_proofs,
        );

        let targets = Some(circuit.targets());

        // 4) Load dummy proof template compatible with the leaf verifier common data
        let dummy_proof_template =
            load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                .map_err(|e| anyhow!("Failed to deserialize dummy proof: {}", e))?;

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: agg_prover_only,
                common: agg_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            leaf_verifier_only: leaf_verifier_data.verifier_only,
            num_leaf_proofs,
            dummy_proof_template,
        })
    }

    /// Create a layer-0 aggregation prover from explicit file paths.
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
    /// We pass the `verify` flag to optionally verify binary integrity using the hashes in `config.json`.
    /// We expose this option because while integrity verification is critical in production, it can add overhead during development when binaries are frequently rebuilt.
    ///
    /// Expected files:
    /// - `aggregated_prover.bin`
    /// - `aggregated_common.bin`
    /// - `common.bin`
    /// - `verifier.bin`
    /// - `dummy_proof.bin`
    /// - `config.json`
    ///
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path, verify: bool) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir).with_context(|| {
            format!(
                "Failed to load config.json for circuit binary integrity verification from {}",
                bins_dir.display()
            )
        })?;
        if verify {
            bins_config.verify_hashes(bins_dir)?;
        }
        let num_leaf_proofs = bins_config.num_leaf_proofs;

        Self::new_from_files(
            &bins_dir.join("aggregated_prover.bin"),
            &bins_dir.join("aggregated_common.bin"),
            &bins_dir.join("common.bin"),
            &bins_dir.join("verifier.bin"),
            &bins_dir.join("dummy_proof.bin"),
            num_leaf_proofs,
        )
    }

    // -------------------------------------------------------------------------
    // Proving API
    // -------------------------------------------------------------------------

    /// Number of leaf proofs aggregated by this layer-0 prover.
    pub fn num_leaf_proofs(&self) -> usize {
        self.num_leaf_proofs
    }

    /// Commit leaf proofs to the aggregation circuit witness.
    ///
    /// This performs:
    /// 1. Padding with dummy proofs
    /// 2. Shuffle (while keeping a real proof in slot 0 if any real proof exists)
    /// 3. Dummy nullifier generation (used only for dummy slots in-circuit)
    /// 4. Witness filling
    ///
    /// # Errors
    /// Returns an error if:
    /// - too many proofs are provided
    /// - prover has already committed once
    /// - padded aggregation would mix non-zero `asset_id` real proofs with dummy proofs (`asset_id=0`)
    pub fn commit(mut self, inputs: Layer0AggregationInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("layer-0 aggregation prover has already committed to inputs");
        };

        let mut proofs = inputs.proofs;

        if proofs.len() > self.num_leaf_proofs {
            bail!(
                "too many proofs: got {}, expected at most {}",
                proofs.len(),
                self.num_leaf_proofs
            );
        }

        // If we're going to pad with dummy proofs (asset_id = 0), ensure real proofs are asset_id=0.
        // (Same guard as the current dynamic aggregator path.)
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            assert_dummy_padding_asset_id_compatible(&proofs)?;
        }

        // Pad with dummy proofs
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }

        // Shuffle proofs to hide dummy positions while preserving a real proof in slot 0 (if any)
        shuffle_proofs_preserving_first_real_layer0(&mut proofs);

        // Generate one dummy nullifier per slot.
        // In-circuit selects these only for dummy proofs.
        let dummy_nullifiers = generate_dummy_nullifiers_for_slots(proofs.len());

        // Fill witness
        fill_layer0_aggregation_witness(
            &mut self.partial_witness,
            &targets,
            &self.leaf_verifier_only,
            &proofs,
            &dummy_nullifiers,
        )?;

        Ok(self)
    }

    /// Generate the aggregated layer-0 proof after `commit(...)`.
    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove layer-0 aggregation circuit: {}", e))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Leaf proof PI layout constants (wormhole leaf circuit).
/// We only need these for quick checks (asset_id and dummy sentinel).
const LEAF_ASSET_ID_PI_INDEX: usize = 0;
const LEAF_BLOCK_HASH_START: usize = 16;

/// Dummy proofs use `block_hash == [0,0,0,0]` as the sentinel in the layer-0 wrapper.
fn is_dummy_leaf_proof(proof: &ProofWithPublicInputs<F, C, D>) -> bool {
    proof
        .public_inputs
        .get(LEAF_BLOCK_HASH_START..LEAF_BLOCK_HASH_START + 4)
        .map(|slice| slice.iter().all(|f| f.is_zero()))
        .unwrap_or(false)
}

/// Shuffle proofs while ensuring a real proof remains in slot 0 (if any real proof exists).
///
/// This mirrors the behavior of `shuffle_proofs_preserving_first_real(...)` but avoids needing
/// a full `AggregationWrapper` impl just for the prover path.
fn shuffle_proofs_preserving_first_real_layer0(proofs: &mut [ProofWithPublicInputs<F, C, D>]) {
    // Find the first real proof
    if let Some(first_real_idx) = proofs.iter().position(|p| !is_dummy_leaf_proof(p)) {
        proofs.swap(0, first_real_idx);
    }

    // Shuffle remaining proofs
    if proofs.len() > 1 {
        let mut rng = rand::thread_rng();
        proofs[1..].shuffle(&mut rng);
    }
}

/// If we're padding with dummy proofs (`asset_id = 0`), real proofs must also use `asset_id = 0`
/// because the layer-0 circuit enforces asset_id equality across all proofs.
fn assert_dummy_padding_asset_id_compatible(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    if let Some(first_real) = proofs.first() {
        let asset_id_f = first_real
            .public_inputs
            .get(LEAF_ASSET_ID_PI_INDEX)
            .ok_or_else(|| {
                anyhow!(
                    "missing asset_id public input at index {}",
                    LEAF_ASSET_ID_PI_INDEX
                )
            })?;

        let real_asset_id: u32 = asset_id_f
            .to_canonical_u64()
            .try_into()
            .context("asset_id in first proof exceeds u32 range")?;

        if real_asset_id != 0 {
            bail!(
                "Real proofs have asset_id={}, but dummy proofs use asset_id=0. \
                 All proofs must have the same asset_id for aggregation.",
                real_asset_id
            );
        }
    }

    Ok(())
}

/// Generate a dummy nullifier for every slot.
///
/// The layer-0 circuit only uses these for dummy slots (`block_hash == 0`) and ignores them
/// for real slots via conditional select.
fn generate_dummy_nullifiers_for_slots(n_slots: usize) -> Vec<[F; 4]> {
    (0..n_slots)
        .map(|_| digest_bytes_to_felts(generate_random_nullifier()))
        .collect()
}
