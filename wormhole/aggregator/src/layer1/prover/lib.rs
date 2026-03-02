//! Layer-1 aggregation prover (prebuilt-circuit proving API).
//!
//! Mirrors the `WormholeProver` / `Layer0AggregationProver` API style:
//! - `new(...)` / `new_from_*`
//! - `commit(...)`
//! - `prove()`

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
            VerifierCircuitData, VerifierOnlyCircuitData,
        },
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use qp_wormhole_inputs::BytesDigest;

#[cfg(feature = "std")]
use std::{fs, path::Path};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::digest_bytes_to_felts,
};

use crate::layer1::{
    circuit::circuit_logic::{Layer1AggregationCircuit, Layer1AggregationCircuitTargets},
    prover::{targets_layout::Layer1TargetsLayoutD, witness::fill_layer1_aggregation_witness},
};

/// Inputs for layer-1 aggregation.
///
/// Takes ownership to avoid unnecessary clones in `commit(...)`.
#[derive(Debug)]
pub struct Layer1AggregationInputs {
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub aggregator_address: BytesDigest,
}

#[derive(Debug)]
pub struct Layer1AggregationProver {
    /// Prebuilt layer-1 circuit prover data.
    pub circuit_data: ProverCircuitData<F, C, D>,

    partial_witness: PartialWitness<F>,

    /// Runtime targets for the prebuilt circuit (consumed on commit).
    targets: Option<Layer1AggregationCircuitTargets>,

    /// Verifier-only data for the child (layer-0) proofs.
    layer0_verifier_only: VerifierOnlyCircuitData<C, D>,

    /// Number of layer-0 proofs expected in one batch.
    num_layer0_proofs: usize,
}

impl Layer1AggregationProver {
    // -------------------------------------------------------------------------
    // Constructors (fresh build path)
    // -------------------------------------------------------------------------

    /// Build a fresh layer-0 aggregation prover from circuit definitions.
    ///
    /// This is the "dev/fallback" path. In production, prefer `new_from_binaries_dir(...)`
    /// or `new_from_files(...)` so the aggregation circuit is prebuilt and loaded to reduce overhead.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        layer1_circuit_config: CircuitConfig,
        layer0_common: CommonCircuitData<F, D>,
        layer0_verifier_only: VerifierOnlyCircuitData<C, D>,
        num_layer0_proofs: usize,
        layer0_num_leaves: usize,
    ) -> Self {
        let l1_circuit = Layer1AggregationCircuit::new(
            layer1_circuit_config,
            layer0_common,
            num_layer0_proofs,
            layer0_num_leaves,
        );

        let targets = Some(l1_circuit.targets());
        let circuit_data = l1_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            layer0_verifier_only,
            num_layer0_proofs,
        }
    }

    // -------------------------------------------------------------------------
    // Constructors (bytes / files)
    // -------------------------------------------------------------------------

    /// Create a layer-1 prover from serialized bytes.
    ///
    /// Expected bytes:
    /// - `layer1_prover_only_bytes`
    /// - `layer1_common_bytes`
    /// - `layer1_targets_bytes` (serialized Layer1TargetsLayoutD)
    /// - `layer0_common_bytes`
    /// - `layer0_verifier_only_bytes`
    pub fn new_from_bytes(
        layer1_prover_only_bytes: &[u8],
        layer1_common_bytes: &[u8],
        layer1_targets_bytes: &[u8],
        layer0_common_bytes: &[u8],
        layer0_verifier_only_bytes: &[u8],
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
            _phantom: Default::default(),
        };

        // 1) Load prebuilt layer-1 circuit prover data
        let l1_common =
            CommonCircuitData::from_bytes(layer1_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize layer1 common data: {}", e))?;

        let l1_prover_only = ProverOnlyCircuitData::from_bytes(
            layer1_prover_only_bytes,
            &generator_serializer,
            &l1_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize layer1 prover data: {}", e))?;

        // 2) Load targets layout
        let layout = Layer1TargetsLayoutD::from_bytes(layer1_targets_bytes)
            .context("Failed to deserialize layer1 targets layout")?;
        let runtime_targets = layout
            .to_runtime()
            .context("Failed to reconstruct layer1 runtime targets")?;

        let targets = Some(Layer1AggregationCircuitTargets {
            layer0_verifier_data: runtime_targets.layer0_verifier_data_t,
            layer0_proofs: runtime_targets.layer0_proof_targets,
            aggregator_address: runtime_targets.aggregator_address_targets,
        });

        // 3) Load layer-0 verifier data (needed for witness filling and dummy proof parsing)
        let layer0_verifier_data =
            load_layer0_verifier_data_from_bytes(layer0_common_bytes, layer0_verifier_only_bytes)?;

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: l1_prover_only,
                common: l1_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            layer0_verifier_only: layer0_verifier_data.verifier_only,
            num_layer0_proofs: layout.n_layer0,
        })
    }

    /// Create a layer-1 prover from explicit file paths.
    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        layer1_prover_path: &Path,
        layer1_common_path: &Path,
        layer1_targets_path: &Path,
        layer0_common_path: &Path,
        layer0_verifier_path: &Path,
    ) -> Result<Self> {
        let layer1_prover_only_bytes = fs::read(layer1_prover_path)
            .with_context(|| format!("Failed to read {:?}", layer1_prover_path))?;
        let layer1_common_bytes = fs::read(layer1_common_path)
            .with_context(|| format!("Failed to read {:?}", layer1_common_path))?;
        let layer1_targets_bytes = fs::read(layer1_targets_path)
            .with_context(|| format!("Failed to read {:?}", layer1_targets_path))?;

        let layer0_common_bytes = fs::read(layer0_common_path)
            .with_context(|| format!("Failed to read {:?}", layer0_common_path))?;
        let layer0_verifier_only_bytes = fs::read(layer0_verifier_path)
            .with_context(|| format!("Failed to read {:?}", layer0_verifier_path))?;

        Self::new_from_bytes(
            &layer1_prover_only_bytes,
            &layer1_common_bytes,
            &layer1_targets_bytes,
            &layer0_common_bytes,
            &layer0_verifier_only_bytes,
        )
    }

    /// Convenience constructor from a generated binaries directory.
    ///
    /// Expected files:
    /// - `layer1_prover.bin`
    /// - `layer1_common.bin`
    /// - `layer1_targets.json`
    /// - `aggregated_common.bin`      (layer-0 common)
    /// - `aggregated_verifier.bin`    (layer-0 verifier-only)
    ///
    /// If `config.json` exists, hash verification is run first.
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let config_path = bins_dir.join("config.json");
        if config_path.exists() {
            let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)?;
            bins_config.verify_hashes(bins_dir)?;
        }

        Self::new_from_files(
            &bins_dir.join("layer1_prover.bin"),
            &bins_dir.join("layer1_common.bin"),
            &bins_dir.join("layer1_targets.json"),
            &bins_dir.join("aggregated_common.bin"),
            &bins_dir.join("aggregated_verifier.bin"),
        )
    }

    // -------------------------------------------------------------------------
    // Proving API
    // -------------------------------------------------------------------------

    pub fn num_layer0_proofs(&self) -> usize {
        self.num_layer0_proofs
    }

    /// Commit layer-0 aggregated proofs into the layer-1 circuit witness
    /// We don't perform dummy padding here since it doesn't serve a privacy preserving purpose like it does for layer 0.
    pub fn commit(mut self, inputs: Layer1AggregationInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("layer-1 aggregation prover has already committed to inputs");
        };

        let proofs = inputs.proofs;
        let aggregator_address = inputs.aggregator_address;

        let aggregator_address_felts = digest_bytes_to_felts(aggregator_address);

        if proofs.len() != self.num_layer0_proofs {
            bail!(
                "Expected {} layer-0 proofs, but got {}",
                self.num_layer0_proofs,
                proofs.len()
            );
        }

        fill_layer1_aggregation_witness(
            &mut self.partial_witness,
            &targets,
            &self.layer0_verifier_only,
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

fn load_layer0_verifier_data_from_bytes(
    layer0_common_bytes: &[u8],
    layer0_verifier_only_bytes: &[u8],
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common = CommonCircuitData::from_bytes(layer0_common_bytes.to_vec(), &gate_serializer)
        .map_err(|e| anyhow!("Failed to deserialize layer0 common data: {}", e))?;

    let verifier_only =
        VerifierOnlyCircuitData::<C, D>::from_bytes(layer0_verifier_only_bytes.to_vec())
            .map_err(|e| anyhow!("Failed to deserialize layer0 verifier-only data: {}", e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
}
