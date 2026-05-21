//! Shipping inner aggregation prover for the compact-child 2x8 layer-0 path.

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData, VerifierCircuitData,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};

#[cfg(feature = "std")]
use std::{fs, path::Path, sync::Arc};

use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::bytes_to_digest;

use crate::{
    common::utils::load_verifier_data_from_bytes,
    common::utils::validate_leaf_proof_public_inputs,
    dummy_proof::{generate_random_nullifier_preimage, load_dummy_proof},
};

use crate::layer0::{
    circuit::{
        constants::{
            INNER_COMMON_FILENAME, INNER_NUM_LEAVES, INNER_OUTPUT_PI_LEN, INNER_PROVER_FILENAME,
            INNER_TARGETS_FILENAME, INNER_VERIFIER_FILENAME, LEAF_PI_LEN,
        },
        inner::{InnerAggregationCircuit, InnerAggregationCircuitTargets},
    },
    prover::{ordering::canonicalize_leaf_proofs, witness::fill_inner_aggregation_witness},
};

type Proof = ProofWithPublicInputs<F, C, D>;

/// Inputs for inner aggregation.
#[derive(Debug)]
pub struct InnerAggregationInputs {
    pub proofs: Vec<Proof>,
}

/// Immutable preloaded artifacts for the non-ZK inner aggregation circuit.
#[derive(Debug, Clone)]
pub struct InnerAggregationArtifacts {
    pub circuit_data: Arc<ProverCircuitData<F, C, D>>,
    pub verifier_data: Arc<VerifierCircuitData<F, C, D>>,
    targets: InnerAggregationCircuitTargets,
    expected_leaf_pi_len: usize,
    dummy_proof_template: Arc<Proof>,
}

impl InnerAggregationArtifacts {
    pub fn new(
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
        dummy_proof_template: Proof,
    ) -> Self {
        let expected_leaf_pi_len = leaf_common.num_public_inputs;
        let circuit = InnerAggregationCircuit::new(leaf_common.clone(), &leaf_verifier_only);
        let targets = circuit.targets();
        let built_circuit = circuit.build_circuit();
        let verifier_data = Arc::new(built_circuit.verifier_data());
        let circuit_data = Arc::new(built_circuit.prover_data());

        Self {
            circuit_data,
            verifier_data,
            targets,
            expected_leaf_pi_len,
            dummy_proof_template: Arc::new(dummy_proof_template),
        }
    }

    pub fn new_from_bytes_with_targets(
        inner_prover_only_bytes: &[u8],
        inner_common_bytes: &[u8],
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
        inner_targets_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        let inner_common =
            CommonCircuitData::from_bytes(inner_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize inner common data: {}", e))?;
        if inner_common.num_public_inputs != INNER_OUTPUT_PI_LEN {
            bail!(
                "inner common public input length mismatch: expected {}, got {}",
                INNER_OUTPUT_PI_LEN,
                inner_common.num_public_inputs
            );
        }

        let inner_prover_only = ProverOnlyCircuitData::from_bytes(
            inner_prover_only_bytes,
            &generator_serializer,
            &inner_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize inner prover data: {}", e))?;

        let leaf_verifier_data =
            load_verifier_data_from_bytes(leaf_common_bytes, leaf_verifier_only_bytes, "leaf")?;
        let expected_leaf_pi_len = leaf_verifier_data.common.num_public_inputs;
        if expected_leaf_pi_len != LEAF_PI_LEN {
            bail!(
                "leaf common public input length mismatch: expected {}, got {}",
                LEAF_PI_LEN,
                expected_leaf_pi_len
            );
        }

        let canonical_circuit = InnerAggregationCircuit::new(
            leaf_verifier_data.common.clone(),
            &leaf_verifier_data.verifier_only,
        );
        let canonical_targets = canonical_circuit.targets();
        let verifier_data = Arc::new(canonical_circuit.build_verifier());

        let targets = match inner_targets_bytes {
            Some(bytes) => {
                let loaded = InnerAggregationCircuitTargets::from_bytes(bytes)
                    .context("failed to deserialize inner target layout")?;
                ensure_inner_targets_match_canonical(&loaded, &canonical_targets)?;
                loaded
            }
            None => canonical_targets,
        };

        let dummy_proof_template =
            load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                .map_err(|e| anyhow!("Failed to deserialize dummy proof: {}", e))?;

        Ok(Self {
            circuit_data: Arc::new(ProverCircuitData {
                prover_only: inner_prover_only,
                common: inner_common,
            }),
            verifier_data,
            targets,
            expected_leaf_pi_len,
            dummy_proof_template: Arc::new(dummy_proof_template),
        })
    }

    pub fn new_from_bytes(
        inner_prover_only_bytes: &[u8],
        inner_common_bytes: &[u8],
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
    ) -> Result<Self> {
        Self::new_from_bytes_with_targets(
            inner_prover_only_bytes,
            inner_common_bytes,
            leaf_common_bytes,
            leaf_verifier_only_bytes,
            dummy_proof_bytes,
            None,
        )
    }

    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        inner_prover_path: &Path,
        inner_common_path: &Path,
        leaf_common_path: &Path,
        leaf_verifier_path: &Path,
        dummy_proof_path: &Path,
    ) -> Result<Self> {
        let inner_prover_only_bytes = fs::read(inner_prover_path)
            .with_context(|| format!("Failed to read {:?}", inner_prover_path))?;
        let inner_common_bytes = fs::read(inner_common_path)
            .with_context(|| format!("Failed to read {:?}", inner_common_path))?;
        let leaf_common_bytes = fs::read(leaf_common_path)
            .with_context(|| format!("Failed to read {:?}", leaf_common_path))?;
        let leaf_verifier_only_bytes = fs::read(leaf_verifier_path)
            .with_context(|| format!("Failed to read {:?}", leaf_verifier_path))?;
        let dummy_proof_bytes = fs::read(dummy_proof_path)
            .with_context(|| format!("Failed to read {:?}", dummy_proof_path))?;

        Self::new_from_bytes(
            &inner_prover_only_bytes,
            &inner_common_bytes,
            &leaf_common_bytes,
            &leaf_verifier_only_bytes,
            &dummy_proof_bytes,
        )
    }

    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let verifier_data = Arc::new(load_inner_verifier_from_binaries_dir(bins_dir)?);

        let inner_prover_only_bytes =
            fs::read(bins_dir.join(INNER_PROVER_FILENAME)).with_context(|| {
                format!(
                    "Failed to read required inner prover artifact {}",
                    bins_dir.join(INNER_PROVER_FILENAME).display()
                )
            })?;
        let inner_common_bytes =
            fs::read(bins_dir.join(INNER_COMMON_FILENAME)).with_context(|| {
                format!(
                    "Failed to read {}",
                    bins_dir.join(INNER_COMMON_FILENAME).display()
                )
            })?;
        let leaf_common_bytes = fs::read(bins_dir.join("common.bin"))
            .with_context(|| format!("Failed to read {}", bins_dir.join("common.bin").display()))?;
        let leaf_verifier_only_bytes =
            fs::read(bins_dir.join("verifier.bin")).with_context(|| {
                format!("Failed to read {}", bins_dir.join("verifier.bin").display())
            })?;
        let dummy_proof_bytes = fs::read(bins_dir.join("dummy_proof.bin")).with_context(|| {
            format!(
                "Failed to read {}",
                bins_dir.join("dummy_proof.bin").display()
            )
        })?;
        let inner_targets_bytes = read_optional_targets_file(bins_dir)?;

        let mut artifacts = Self::new_from_bytes_with_targets(
            &inner_prover_only_bytes,
            &inner_common_bytes,
            &leaf_common_bytes,
            &leaf_verifier_only_bytes,
            &dummy_proof_bytes,
            inner_targets_bytes.as_deref(),
        )?;
        artifacts.verifier_data = verifier_data;
        Ok(artifacts)
    }

    pub fn expected_leaf_pi_len(&self) -> usize {
        self.expected_leaf_pi_len
    }

    pub fn num_leaf_proofs(&self) -> usize {
        INNER_NUM_LEAVES
    }

    pub fn new_session(&self) -> InnerAggregationProver {
        InnerAggregationProver::from_artifacts(self)
    }
}

fn ensure_inner_targets_match_canonical(
    loaded: &InnerAggregationCircuitTargets,
    canonical: &InnerAggregationCircuitTargets,
) -> Result<()> {
    let loaded_bytes = loaded
        .to_bytes()
        .context("failed to serialize loaded inner target layout for validation")?;
    let canonical_bytes = canonical
        .to_bytes()
        .context("failed to serialize canonical inner target layout for validation")?;
    if loaded_bytes != canonical_bytes {
        bail!("inner target layout does not match the compiled compact-child 2x8 topology");
    }
    Ok(())
}

/// Mutable proving session backed by cached inner artifacts.
#[derive(Debug)]
pub struct InnerAggregationProver {
    pub circuit_data: Arc<ProverCircuitData<F, C, D>>,
    partial_witness: PartialWitness<F>,
    targets: Option<InnerAggregationCircuitTargets>,
    dummy_proof_template: Arc<Proof>,
}

impl InnerAggregationProver {
    pub fn from_artifacts(artifacts: &InnerAggregationArtifacts) -> Self {
        Self {
            circuit_data: Arc::clone(&artifacts.circuit_data),
            partial_witness: PartialWitness::new(),
            targets: Some(artifacts.targets.clone()),
            dummy_proof_template: Arc::clone(&artifacts.dummy_proof_template),
        }
    }

    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        Ok(InnerAggregationArtifacts::new_from_binaries_dir(bins_dir)?.new_session())
    }

    pub fn commit(mut self, inputs: InnerAggregationInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("inner aggregation prover has already committed to inputs");
        };

        let mut proofs = inputs.proofs;
        if proofs.len() > self.num_leaf_proofs() {
            bail!(
                "too many proofs: got {}, expected at most {}",
                proofs.len(),
                self.num_leaf_proofs()
            );
        }
        validate_leaf_proofs_public_inputs(&proofs)?;

        let num_dummies_needed = self.num_leaf_proofs().saturating_sub(proofs.len());

        for _ in 0..num_dummies_needed {
            proofs.push((*self.dummy_proof_template).clone());
        }

        canonicalize_proofs_preserving_first_real_inner(&mut proofs);
        let dummy_nullifier_pre_images =
            generate_dummy_nullifier_pre_images_for_slots(proofs.len());

        fill_inner_aggregation_witness(
            &mut self.partial_witness,
            &targets,
            &proofs,
            &dummy_nullifier_pre_images,
        )?;

        Ok(self)
    }

    pub fn prove(self) -> Result<Proof> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove inner aggregation circuit: {}", e))
    }

    pub fn dummy_nullifier_pre_image(&self) -> [F; 4] {
        bytes_to_digest(generate_random_nullifier_preimage())
    }
}

impl InnerAggregationProver {
    pub fn num_leaf_proofs(&self) -> usize {
        INNER_NUM_LEAVES
    }
}

/// Load the verifier artifacts for the inner topology from a generated bins directory.
pub fn load_inner_verifier_from_binaries_dir(
    bins_dir: &Path,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = fs::read(bins_dir.join(INNER_COMMON_FILENAME)).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join(INNER_COMMON_FILENAME).display()
        )
    })?;
    let common = CommonCircuitData::from_bytes(common_bytes, &gate_serializer)
        .map_err(|e| anyhow!("Failed to deserialize inner common data: {}", e))?;
    if common.num_public_inputs != INNER_OUTPUT_PI_LEN {
        bail!(
            "inner common public input length mismatch: expected {}, got {}",
            INNER_OUTPUT_PI_LEN,
            common.num_public_inputs
        );
    }

    let verifier_bytes = fs::read(bins_dir.join(INNER_VERIFIER_FILENAME)).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join(INNER_VERIFIER_FILENAME).display()
        )
    })?;
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_bytes)
        .map_err(|e| anyhow!("Failed to deserialize inner verifier data: {}", e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
}

/// Canonicalizes inner proof ordering for the compact-child 2x8 topology.
///
/// The deterministic ordering is intentional. Real proofs sort before dummy padding so slot `0`
/// remains real when a real proof exists, and each partition is sorted by canonical public inputs
/// so witness construction stays deterministic and reproducible. These non-ZK inner proofs are an
/// internal proving stage consumed by the final outer ZK wrapper, so proof order must not be treated
/// as a privacy boundary. If inner proofs ever become externally exposed, this ordering decision
/// must be revisited.
fn canonicalize_proofs_preserving_first_real_inner(proofs: &mut [Proof]) {
    canonicalize_leaf_proofs(proofs);
}

fn validate_leaf_proofs_public_inputs(proofs: &[Proof]) -> Result<()> {
    for proof in proofs {
        validate_leaf_proof_public_inputs(proof, "leaf proof")?;
    }

    Ok(())
}

fn generate_dummy_nullifier_pre_images_for_slots(n_slots: usize) -> Vec<[F; 4]> {
    (0..n_slots)
        .map(|_| bytes_to_digest(generate_random_nullifier_preimage()))
        .collect()
}

#[cfg(feature = "std")]
fn read_optional_targets_file(bins_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = bins_dir.join(INNER_TARGETS_FILENAME);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow!("Failed to read {}: {}", path.display(), err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer0::circuit::constants::{
        ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START, LEAF_PI_LEN,
        NULLIFIER_START, OUTPUT_AMOUNT_1_START, VOLUME_FEE_BPS_START,
    };
    use plonky2::field::types::Field;
    use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

    #[test]
    fn zero_exit_positive_amount_is_rejected_before_inner_witness_filling() {
        let (data, targets) = build_fake_leaf_circuit();
        let dummy = prove_fake_leaf(&data, &targets, dummy_leaf_pi());
        let bad = prove_fake_leaf(&data, &targets, zero_exit_positive_leaf_pi());
        let artifacts =
            InnerAggregationArtifacts::new(data.common.clone(), data.verifier_only.clone(), dummy);

        let err = artifacts
            .new_session()
            .commit(InnerAggregationInputs { proofs: vec![bad] })
            .unwrap_err();

        assert!(
            err.to_string().contains("zero exit_account"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregator_uses_nonzero_asset_with_dummy_padding() {
        let (data, targets) = build_fake_leaf_circuit();
        let dummy = prove_fake_leaf(&data, &targets, dummy_leaf_pi());
        let real = prove_fake_leaf(&data, &targets, real_leaf_pi(7));
        let artifacts =
            InnerAggregationArtifacts::new(data.common.clone(), data.verifier_only.clone(), dummy);

        let proof = artifacts
            .new_session()
            .commit(InnerAggregationInputs { proofs: vec![real] })
            .unwrap()
            .prove()
            .unwrap();

        artifacts.verifier_data.verify(proof.clone()).unwrap();
        assert_eq!(
            proof.public_inputs
                [crate::layer0::circuit::constants::aggregated_output::ASSET_ID_OFFSET],
            F::from_canonical_u64(7)
        );
    }

    #[test]
    fn validation_rejects_malformed_public_input_length_in_full_inner_batch() {
        let (data, targets) = build_fake_leaf_circuit();
        let dummy = prove_fake_leaf(&data, &targets, dummy_leaf_pi());
        let mut proofs = (0..INNER_NUM_LEAVES)
            .map(|_| prove_fake_leaf(&data, &targets, real_leaf_pi(0)))
            .collect::<Vec<_>>();
        proofs[3].public_inputs.pop();
        let artifacts =
            InnerAggregationArtifacts::new(data.common.clone(), data.verifier_only.clone(), dummy);

        let err = artifacts
            .new_session()
            .commit(InnerAggregationInputs { proofs })
            .unwrap_err();

        assert!(
            err.to_string().contains("public input length mismatch"),
            "unexpected error: {err}"
        );
    }

    fn zero_exit_positive_leaf_pi() -> [F; LEAF_PI_LEN] {
        let mut public_inputs = [F::ZERO; LEAF_PI_LEN];
        public_inputs[ASSET_ID_START] = F::ZERO;
        public_inputs[OUTPUT_AMOUNT_1_START] = F::from_canonical_u64(11);
        public_inputs[VOLUME_FEE_BPS_START] = F::from_canonical_u64(10);
        public_inputs[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&digest(100));
        public_inputs[EXIT_1_START..EXIT_1_START + 4].copy_from_slice(&[F::ZERO; 4]);
        public_inputs[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&digest(200));
        public_inputs[BLOCK_NUMBER_START] = F::from_canonical_u64(99);
        public_inputs
    }

    fn real_leaf_pi(asset_id: u64) -> [F; LEAF_PI_LEN] {
        let mut public_inputs = [F::ZERO; LEAF_PI_LEN];
        public_inputs[ASSET_ID_START] = F::from_canonical_u64(asset_id);
        public_inputs[OUTPUT_AMOUNT_1_START] = F::from_canonical_u64(11);
        public_inputs[VOLUME_FEE_BPS_START] = F::from_canonical_u64(10);
        public_inputs[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&digest(100));
        public_inputs[EXIT_1_START..EXIT_1_START + 4].copy_from_slice(&digest(150));
        public_inputs[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&digest(200));
        public_inputs[BLOCK_NUMBER_START] = F::from_canonical_u64(99);
        public_inputs
    }

    fn dummy_leaf_pi() -> [F; LEAF_PI_LEN] {
        let mut public_inputs = [F::ZERO; LEAF_PI_LEN];
        public_inputs[VOLUME_FEE_BPS_START] = F::from_canonical_u64(10);
        public_inputs
    }

    fn digest(seed: u64) -> [F; 4] {
        core::array::from_fn(|idx| F::from_canonical_u64(seed + idx as u64))
    }
}
