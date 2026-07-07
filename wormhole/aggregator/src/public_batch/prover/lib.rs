//! Public-batch aggregation prover (prebuilt-circuit proving API).
//!
//! The private-batch verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.

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
    common::utils::load_verifier_data_from_bytes,
    public_batch::{
        circuit::circuit_logic::{PublicBatchCircuit, PublicBatchCircuitTargets},
        prover::witness::fill_public_batch_witness,
    },
};

#[derive(Debug)]
pub struct PublicBatchInputs {
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub aggregator_address: BytesDigest,
}

#[derive(Debug)]
pub struct PublicBatchProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<PublicBatchCircuitTargets>,
    num_private_batch_proofs: usize,
    /// Dummy private-batch proof (over all-dummy leaves, `block_hash == 0`) used to
    /// pad partial public batches. The circuit zeroes dummy inners' exit slots and
    /// nullifiers, so one template can fill several slots without collisions.
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
}

impl PublicBatchProver {
    /// Build a fresh public-batch aggregation prover from circuit definitions.
    ///
    /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_batch_circuit_config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_private_batch_proofs: usize,
        private_batch_num_leaves: usize,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let public_batch_circuit = PublicBatchCircuit::new(
            public_batch_circuit_config,
            private_batch_common,
            private_batch_verifier_only,
            num_private_batch_proofs,
            private_batch_num_leaves,
        );

        let targets = Some(public_batch_circuit.targets());
        let circuit_data = public_batch_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            num_private_batch_proofs,
            dummy_proof_template,
        }
    }

    /// Create a public-batch prover from serialized bytes.
    pub fn new_from_bytes(
        public_batch_prover_only_bytes: &[u8],
        public_batch_common_bytes: &[u8],
        private_batch_common_bytes: &[u8],
        private_batch_verifier_only_bytes: &[u8],
        dummy_private_batch_proof_bytes: &[u8],
        config: (usize, usize), // (num_leaf_proofs, num_private_batch_proofs)
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        // 1) Load prebuilt public-batch circuit prover data
        let public_batch_common =
            CommonCircuitData::from_bytes(public_batch_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("failed to deserialize public_batch common data: {}", e))?;

        let public_batch_prover_only = ProverOnlyCircuitData::from_bytes(
            public_batch_prover_only_bytes,
            &generator_serializer,
            &public_batch_common,
        )
        .map_err(|e| anyhow!("failed to deserialize public_batch prover data: {}", e))?;

        // 2) Load private-batch verifier data (needed for witness filling and dummy proof parsing)
        let private_batch_verifier_data = load_verifier_data_from_bytes(
            private_batch_common_bytes,
            private_batch_verifier_only_bytes,
            "private_batch",
        )?;

        let (num_leaf_proofs, num_private_batch_proofs) = config;

        let circuit = PublicBatchCircuit::new(
            public_batch_common.config.clone(),
            private_batch_verifier_data.common.clone(),
            &private_batch_verifier_data.verifier_only,
            num_private_batch_proofs,
            num_leaf_proofs,
        );

        let targets = Some(circuit.targets());

        // 3) Load the dummy private-batch proof template used to pad partial batches
        let dummy_proof_template = ProofWithPublicInputs::<F, C, D>::from_bytes(
            dummy_private_batch_proof_bytes.to_vec(),
            &private_batch_verifier_data.common,
        )
        .map_err(|e| anyhow!("failed to deserialize dummy private-batch proof: {}", e))?;

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: public_batch_prover_only,
                common: public_batch_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            num_private_batch_proofs,
            dummy_proof_template,
        })
    }

    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        public_batch_prover_path: &Path,
        public_batch_common_path: &Path,
        private_batch_common_path: &Path,
        private_batch_verifier_path: &Path,
        dummy_private_batch_proof_path: &Path,
        config: (usize, usize),
    ) -> Result<Self> {
        let public_batch_prover_only_bytes = fs::read(public_batch_prover_path)
            .with_context(|| format!("Failed to read {:?}", public_batch_prover_path))?;
        let public_batch_common_bytes = fs::read(public_batch_common_path)
            .with_context(|| format!("Failed to read {:?}", public_batch_common_path))?;

        let private_batch_common_bytes = fs::read(private_batch_common_path)
            .with_context(|| format!("Failed to read {:?}", private_batch_common_path))?;
        let private_batch_verifier_only_bytes = fs::read(private_batch_verifier_path)
            .with_context(|| format!("Failed to read {:?}", private_batch_verifier_path))?;
        let dummy_private_batch_proof_bytes = fs::read(dummy_private_batch_proof_path)
            .with_context(|| format!("Failed to read {:?}", dummy_private_batch_proof_path))?;

        Self::new_from_bytes(
            &public_batch_prover_only_bytes,
            &public_batch_common_bytes,
            &private_batch_common_bytes,
            &private_batch_verifier_only_bytes,
            &dummy_private_batch_proof_bytes,
            config,
        )
    }

    /// Convenience constructor from a generated binaries directory.
    ///
    /// Expected files:
    /// - `public_batch_prover.bin`
    /// - `public_batch_common.bin`
    /// - `private_batch_common.bin`             (private-batch common)
    /// - `private_batch_verifier.bin`           (private-batch verifier-only)
    /// - `dummy_private_batch_proof.bin`        (padding template)
    /// - `config.json`
    ///
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)?;

        let num_private_batch_proofs = bins_config.num_private_batch_proofs.ok_or_else(|| {
            anyhow!(
                "config is missing num_private_batch_proofs. Regenerate binaries with num_private_batch_proofs set."
            )
        })?;
        let config = (bins_config.num_leaf_proofs, num_private_batch_proofs);

        Self::new_from_files(
            &bins_dir.join("public_batch_prover.bin"),
            &bins_dir.join("public_batch_common.bin"),
            &bins_dir.join("private_batch_common.bin"),
            &bins_dir.join("private_batch_verifier.bin"),
            &bins_dir.join("dummy_private_batch_proof.bin"),
            config,
        )
    }

    pub fn num_private_batch_proofs(&self) -> usize {
        self.num_private_batch_proofs
    }

    /// Commit private-batch aggregated proofs into the public-batch circuit witness.
    ///
    /// Partial batches are padded with the dummy private-batch proof template.
    /// The circuit exempts dummies (`block_hash == 0`) from metadata consistency
    /// and zeroes their forwarded exit slots and nullifiers.
    pub fn commit(mut self, inputs: PublicBatchInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("public-batch aggregation prover has already committed to inputs");
        };

        let mut proofs = inputs.proofs;
        let aggregator_address = inputs.aggregator_address;

        let aggregator_address_felts = bytes_to_digest(aggregator_address);

        if proofs.is_empty() {
            bail!("no private-batch proofs to aggregate");
        }
        if proofs.len() > self.num_private_batch_proofs {
            bail!(
                "Expected at most {} private-batch proofs, but got {}",
                self.num_private_batch_proofs,
                proofs.len()
            );
        }

        // Pad partial batches with the dummy template. No shuffle: forwarding is
        // order-preserving by design (per-segment attribution on-chain).
        let num_dummies_needed = self.num_private_batch_proofs - proofs.len();
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }

        fill_public_batch_witness(
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
            .map_err(|e| anyhow!("Failed to prove public-batch aggregation circuit: {}", e))
    }
}
