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
use std::{fs, io::ErrorKind, path::Path, sync::Arc};
use zk_circuits_common::circuit::{C, D, F};

use crate::{
    common::utils::{ensure_proof_public_input_len, load_verifier_data_from_bytes},
    layer0::{
        circuit::{
            constants::{
                INNER_COMMON_FILENAME, INNER_VERIFIER_FILENAME, OUTER_CHILD_PI_LEN,
                OUTER_COMMON_FILENAME, OUTER_INNER_PROOFS, OUTER_PROVER_FILENAME,
                OUTER_TARGETS_FILENAME, OUTER_VERIFIER_FILENAME,
            },
            outer::{OuterAggregationCircuit, OuterAggregationCircuitTargets},
        },
        prover::witness::fill_outer_aggregation_witness,
    },
};

type Proof = ProofWithPublicInputs<F, C, D>;

#[derive(Debug)]
pub struct OuterAggregationInputs {
    pub proofs: Vec<Proof>,
}

#[derive(Debug, Clone)]
pub struct OuterAggregationArtifacts {
    pub circuit_data: Arc<ProverCircuitData<F, C, D>>,
    pub verifier_data: Arc<VerifierCircuitData<F, C, D>>,
    targets: OuterAggregationCircuitTargets,
    inner_verifier_only: Arc<VerifierOnlyCircuitData<C, D>>,
}

impl OuterAggregationArtifacts {
    pub fn new(
        inner_common: CommonCircuitData<F, D>,
        inner_verifier_only: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let circuit = OuterAggregationCircuit::new(inner_common.clone());
        let targets = circuit.targets();
        let circuit_data = Arc::new(circuit.build_prover());
        let verifier_data = Arc::new(OuterAggregationCircuit::new(inner_common).build_verifier());

        Self {
            circuit_data,
            verifier_data,
            targets,
            inner_verifier_only: Arc::new(inner_verifier_only),
        }
    }

    pub fn new_from_bytes_with_targets(
        outer_prover_only_bytes: &[u8],
        outer_common_bytes: &[u8],
        inner_common_bytes: &[u8],
        inner_verifier_only_bytes: &[u8],
        outer_targets_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        let outer_common =
            CommonCircuitData::from_bytes(outer_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("Failed to deserialize outer common data: {}", e))?;
        let outer_prover_only = ProverOnlyCircuitData::from_bytes(
            outer_prover_only_bytes,
            &generator_serializer,
            &outer_common,
        )
        .map_err(|e| anyhow!("Failed to deserialize outer prover data: {}", e))?;

        let inner_verifier_data =
            load_verifier_data_from_bytes(inner_common_bytes, inner_verifier_only_bytes, "inner")?;

        let targets = match outer_targets_bytes {
            Some(bytes) => OuterAggregationCircuitTargets::from_bytes(bytes)
                .context("failed to deserialize outer target layout")?,
            None => OuterAggregationCircuit::new(inner_verifier_data.common.clone()).targets(),
        };

        Ok(Self {
            circuit_data: Arc::new(ProverCircuitData {
                prover_only: outer_prover_only,
                common: outer_common,
            }),
            verifier_data: Arc::new(
                OuterAggregationCircuit::new(inner_verifier_data.common.clone()).build_verifier(),
            ),
            targets,
            inner_verifier_only: Arc::new(inner_verifier_data.verifier_only),
        })
    }

    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let outer_prover_only_bytes =
            fs::read(bins_dir.join(OUTER_PROVER_FILENAME)).with_context(|| {
                format!(
                    "Failed to read {}",
                    bins_dir.join(OUTER_PROVER_FILENAME).display()
                )
            })?;
        let outer_common_bytes =
            fs::read(bins_dir.join(OUTER_COMMON_FILENAME)).with_context(|| {
                format!(
                    "Failed to read {}",
                    bins_dir.join(OUTER_COMMON_FILENAME).display()
                )
            })?;
        let inner_common_bytes =
            fs::read(bins_dir.join(INNER_COMMON_FILENAME)).with_context(|| {
                format!(
                    "Failed to read {}",
                    bins_dir.join(INNER_COMMON_FILENAME).display()
                )
            })?;
        let inner_verifier_only_bytes = fs::read(bins_dir.join(INNER_VERIFIER_FILENAME))
            .with_context(|| {
                format!(
                    "Failed to read {}",
                    bins_dir.join(INNER_VERIFIER_FILENAME).display()
                )
            })?;
        let outer_targets_bytes = read_optional_targets_file(bins_dir)?;
        let verifier_data = Arc::new(load_outer_verifier_from_binaries_dir(bins_dir)?);

        let mut artifacts = Self::new_from_bytes_with_targets(
            &outer_prover_only_bytes,
            &outer_common_bytes,
            &inner_common_bytes,
            &inner_verifier_only_bytes,
            outer_targets_bytes.as_deref(),
        )?;
        artifacts.verifier_data = verifier_data;
        Ok(artifacts)
    }

    pub fn new_session(&self) -> OuterAggregationProver {
        OuterAggregationProver::from_artifacts(self)
    }
}

#[derive(Debug)]
pub struct OuterAggregationProver {
    pub circuit_data: Arc<ProverCircuitData<F, C, D>>,
    partial_witness: PartialWitness<F>,
    targets: Option<OuterAggregationCircuitTargets>,
    inner_verifier_only: Arc<VerifierOnlyCircuitData<C, D>>,
}

impl OuterAggregationProver {
    pub fn from_artifacts(artifacts: &OuterAggregationArtifacts) -> Self {
        Self {
            circuit_data: Arc::clone(&artifacts.circuit_data),
            partial_witness: PartialWitness::new(),
            targets: Some(artifacts.targets.clone()),
            inner_verifier_only: Arc::clone(&artifacts.inner_verifier_only),
        }
    }

    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        Ok(OuterAggregationArtifacts::new_from_binaries_dir(bins_dir)?.new_session())
    }

    pub fn commit(mut self, inputs: OuterAggregationInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("outer aggregation prover has already committed to inputs");
        };
        let proofs = inputs.proofs;
        if proofs.len() != OUTER_INNER_PROOFS {
            bail!(
                "expected {} inner proofs, got {}",
                OUTER_INNER_PROOFS,
                proofs.len()
            );
        }
        for proof in &proofs {
            ensure_proof_public_input_len(proof, OUTER_CHILD_PI_LEN, "inner proof")?;
        }

        fill_outer_aggregation_witness(
            &mut self.partial_witness,
            &targets,
            &self.inner_verifier_only,
            &proofs,
        )?;

        Ok(self)
    }

    pub fn prove(self) -> Result<Proof> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove outer aggregation circuit: {}", e))
    }
}

pub fn load_outer_verifier_from_binaries_dir(
    bins_dir: &Path,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = fs::read(bins_dir.join(OUTER_COMMON_FILENAME)).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join(OUTER_COMMON_FILENAME).display()
        )
    })?;
    let common = CommonCircuitData::from_bytes(common_bytes, &gate_serializer)
        .map_err(|e| anyhow!("Failed to deserialize outer common data: {}", e))?;

    let verifier_bytes = fs::read(bins_dir.join(OUTER_VERIFIER_FILENAME)).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join(OUTER_VERIFIER_FILENAME).display()
        )
    })?;
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_bytes)
        .map_err(|e| anyhow!("Failed to deserialize outer verifier data: {}", e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
}

#[cfg(feature = "std")]
fn read_optional_targets_file(bins_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = bins_dir.join(OUTER_TARGETS_FILENAME);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow!("Failed to read {}: {}", path.display(), err)),
    }
}
