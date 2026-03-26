//! Layer-1 aggregation prover (prebuilt-circuit proving API).
//!
//! Mirrors the `WormholeProver` / `Layer0AggregationProver` API style:
//! - `new(...)` / `new_from_*`
//! - `commit(...)`
//! - `prove()`

use anyhow::{anyhow, bail, Context, Result};
#[cfg(feature = "std")]
use plonky2::{
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
use qp_wormhole_inputs::BytesDigest;

#[cfg(feature = "std")]
use std::{fs, path::Path};

use zk_circuits_common::{
    circuit::{C, D, F},
    utils::bytes_to_digest,
};

use crate::{
    common::utils::load_verifier_data_from_bytes,
    layer1::{
        circuit::circuit_logic::{Layer1AggregationCircuit, Layer1AggregationCircuitTargets},
        prover::witness::fill_layer1_aggregation_witness,
    },
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

    /// Build a fresh layer-1 aggregation prover from circuit definitions.
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
    /// - `layer0_common_bytes`
    /// - `layer0_verifier_only_bytes`
    /// - `config` tuple: (num_leaf_proofs, num_layer0_proofs)
    pub fn new_from_bytes(
        layer1_prover_only_bytes: &[u8],
        layer1_common_bytes: &[u8],
        layer0_common_bytes: &[u8],
        layer0_verifier_only_bytes: &[u8],
        config: (usize, usize), // (num_leaf_proofs, num_layer0_proofs)
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

        // 2) Load layer-0 verifier data (needed for witness filling and dummy proof parsing)
        let layer0_verifier_data = load_verifier_data_from_bytes(
            layer0_common_bytes,
            layer0_verifier_only_bytes,
            "layer0",
        )?;

        // 3) Create circuit and get targets

        let (num_leaf_proofs, num_layer0_proofs) = config;

        let circuit = Layer1AggregationCircuit::new(
            l1_common.config.clone(),
            layer0_verifier_data.common.clone(),
            num_layer0_proofs,
            num_leaf_proofs,
        );

        let targets = Some(circuit.targets());

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: l1_prover_only,
                common: l1_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            layer0_verifier_only: layer0_verifier_data.verifier_only,
            num_layer0_proofs,
        })
    }

    /// Create a layer-1 prover from explicit file paths.
    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        layer1_prover_path: &Path,
        layer1_common_path: &Path,
        layer0_common_path: &Path,
        layer0_verifier_path: &Path,
        config: (usize, usize), // (num_leaf_proofs, num_layer0_proofs)
    ) -> Result<Self> {
        let layer1_prover_only_bytes = fs::read(layer1_prover_path)
            .with_context(|| format!("Failed to read {:?}", layer1_prover_path))?;
        let layer1_common_bytes = fs::read(layer1_common_path)
            .with_context(|| format!("Failed to read {:?}", layer1_common_path))?;

        let layer0_common_bytes = fs::read(layer0_common_path)
            .with_context(|| format!("Failed to read {:?}", layer0_common_path))?;
        let layer0_verifier_only_bytes = fs::read(layer0_verifier_path)
            .with_context(|| format!("Failed to read {:?}", layer0_verifier_path))?;

        Self::new_from_bytes(
            &layer1_prover_only_bytes,
            &layer1_common_bytes,
            &layer0_common_bytes,
            &layer0_verifier_only_bytes,
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
            config,
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

        // Use 8 bytes/felt encoding for hash-derived account addresses
        let aggregator_address_felts = bytes_to_digest(aggregator_address);

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
