use anyhow::{bail, Context, Result};
use plonky2::{
    plonk::{
        circuit_data::CommonCircuitData, circuit_data::VerifierCircuitData,
        proof::ProofWithPublicInputs,
    },
    util::serialization::DefaultGateSerializer,
};
#[cfg(feature = "multithread")]
use rayon::ThreadPoolBuilder;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};
use zk_circuits_common::circuit::{C, D, F};

use crate::{
    common::utils::is_dummy_leaf_proof,
    layer0::{
        circuit::constants::{INNER_NUM_LEAVES, TOTAL_NUM_LEAVES},
        prover::{
            inner::{
                load_inner_verifier_from_binaries_dir, InnerAggregationArtifacts,
                InnerAggregationInputs,
            },
            outer::{
                load_outer_verifier_from_binaries_dir, OuterAggregationArtifacts,
                OuterAggregationInputs,
            },
        },
    },
};

type Proof = ProofWithPublicInputs<F, C, D>;

pub const AGGREGATED_TARGETS_FILENAME: &str = "aggregated_targets.bin";

#[derive(Debug, Clone, Copy)]
pub enum InnerExecutionMode {
    Serial,
    Parallel,
}

#[derive(Debug, Clone, Default)]
pub struct StageTiming {
    pub commit_ms: f64,
    pub prove_ms: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Layer0Timing {
    pub inner_a: StageTiming,
    pub inner_b: StageTiming,
    pub outer: StageTiming,
    pub total_ms: f64,
}

#[derive(Debug)]
pub struct Layer0AggregateOutput {
    pub proof: Proof,
    pub timing: Layer0Timing,
}

#[derive(Debug, Clone)]
pub struct Layer0AggregationArtifacts {
    bins_dir: PathBuf,
    expected_leaf_pi_len: usize,
    inner_artifacts: InnerAggregationArtifacts,
    outer_artifacts: OuterAggregationArtifacts,
    outer_verifier: VerifierCircuitData<F, C, D>,
}

#[derive(Debug)]
pub struct Layer0AggregationProver {
    artifacts: Layer0AggregationArtifacts,
    proofs: Option<Vec<Proof>>,
    mode: InnerExecutionMode,
}

impl Layer0AggregationArtifacts {
    pub fn new_from_binaries_dir<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();
        let inner_artifacts = InnerAggregationArtifacts::new_from_binaries_dir(&bins_dir)
            .context("failed to load shipping inner artifacts")?;
        let outer_artifacts = OuterAggregationArtifacts::new_from_binaries_dir(&bins_dir)
            .context("failed to load shipping outer artifacts")?;
        let outer_verifier = load_outer_verifier_from_binaries_dir(&bins_dir)
            .context("failed to load layer-0 outer verifier")?;
        let leaf_common = load_common_from_bins(&bins_dir, "common.bin")?;
        let _ = load_inner_verifier_from_binaries_dir(&bins_dir)
            .context("failed to load layer-0 inner verifier")?;

        Ok(Self {
            bins_dir,
            expected_leaf_pi_len: leaf_common.num_public_inputs,
            inner_artifacts,
            outer_artifacts,
            outer_verifier,
        })
    }

    pub fn bins_dir(&self) -> &Path {
        &self.bins_dir
    }

    pub fn expected_leaf_pi_len(&self) -> usize {
        self.expected_leaf_pi_len
    }

    pub fn num_leaf_proofs(&self) -> usize {
        TOTAL_NUM_LEAVES
    }

    pub fn verify(&self, proof: Proof) -> Result<()> {
        self.outer_verifier
            .verify(proof)
            .map_err(|e| anyhow::anyhow!("layer-0 proof verification failed: {}", e))
    }

    pub fn new_session(&self) -> Layer0AggregationProver {
        Layer0AggregationProver::from_artifacts(self)
    }
}

impl Layer0AggregationProver {
    pub fn from_artifacts(artifacts: &Layer0AggregationArtifacts) -> Self {
        Self {
            artifacts: artifacts.clone(),
            proofs: None,
            mode: InnerExecutionMode::Parallel,
        }
    }

    pub fn new_from_binaries_dir<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        Ok(Layer0AggregationArtifacts::new_from_binaries_dir(bins_dir)?.new_session())
    }

    pub fn with_inner_execution_mode(mut self, mode: InnerExecutionMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn commit(mut self, proofs: Vec<Proof>) -> Result<Self> {
        if proofs.is_empty() {
            bail!("there are no leaf proofs to aggregate");
        }
        if proofs.len() > self.artifacts.num_leaf_proofs() {
            bail!(
                "too many proofs for shipping 2x8 layer-0: got {}, expected at most {}",
                proofs.len(),
                self.artifacts.num_leaf_proofs()
            );
        }

        self.proofs = Some(proofs);
        Ok(self)
    }

    pub fn prove(self) -> Result<Proof> {
        let Self {
            artifacts,
            proofs,
            mode,
        } = self;
        let proofs =
            proofs.ok_or_else(|| anyhow::anyhow!("layer-0 prover has no committed proofs"))?;
        Ok(aggregate_with_artifacts(&artifacts, proofs, mode)?.proof)
    }

    pub fn verify(&self, proof: Proof) -> Result<()> {
        self.artifacts.verify(proof)
    }

    pub fn aggregate(
        &self,
        proofs: Vec<Proof>,
        mode: InnerExecutionMode,
    ) -> Result<Layer0AggregateOutput> {
        aggregate_with_artifacts(&self.artifacts, proofs, mode)
    }
}

fn aggregate_with_artifacts(
    artifacts: &Layer0AggregationArtifacts,
    proofs: Vec<Proof>,
    mode: InnerExecutionMode,
) -> Result<Layer0AggregateOutput> {
    if proofs.is_empty() {
        bail!("there are no leaf proofs to aggregate");
    }
    if proofs.len() > TOTAL_NUM_LEAVES {
        bail!(
            "too many proofs for shipping 2x8 layer-0: got {}, expected at most {}",
            proofs.len(),
            TOTAL_NUM_LEAVES
        );
    }

    let mut proofs = proofs;
    normalize_proofs_for_inner_split(&mut proofs);
    let (group_a, group_b) = split_proofs(proofs);
    let start = Instant::now();
    let (inner_a_proof, inner_a_timing, inner_b_proof, inner_b_timing) = match mode {
        InnerExecutionMode::Serial => {
            let (proof_a, timing_a) =
                prove_inner_batch(&artifacts.inner_artifacts, group_a).context("inner A failed")?;
            let (proof_b, timing_b) =
                prove_inner_batch(&artifacts.inner_artifacts, group_b).context("inner B failed")?;
            (proof_a, timing_a, proof_b, timing_b)
        }
        InnerExecutionMode::Parallel => {
            prove_parallel_batches(&artifacts.inner_artifacts, group_a, group_b)?
        }
    };

    let (outer_session, outer_commit_ms) = time_operation(|| {
        artifacts
            .outer_artifacts
            .new_session()
            .commit(OuterAggregationInputs {
                proofs: vec![inner_a_proof, inner_b_proof],
            })
            .context("outer commit failed")
    })?;
    let (proof, outer_prove_ms) =
        time_operation(|| outer_session.prove().context("outer prove failed"))?;

    artifacts.verify(proof.clone())?;

    Ok(Layer0AggregateOutput {
        proof,
        timing: Layer0Timing {
            inner_a: inner_a_timing,
            inner_b: inner_b_timing,
            outer: StageTiming {
                commit_ms: outer_commit_ms,
                prove_ms: outer_prove_ms,
            },
            total_ms: start.elapsed().as_secs_f64() * 1000.0,
        },
    })
}

fn normalize_proofs_for_inner_split(proofs: &mut [Proof]) {
    if let Some(first_real_idx) = proofs
        .iter()
        .position(|proof| !is_dummy_leaf_proof(proof).unwrap_or(false))
    {
        proofs.swap(0, first_real_idx);
    }
}

fn split_proofs(proofs: Vec<Proof>) -> (Vec<Proof>, Vec<Proof>) {
    let mut proofs = proofs;
    let split_at = proofs.len().min(INNER_NUM_LEAVES);
    let group_b = proofs.split_off(split_at);
    (proofs, group_b)
}

fn prove_inner_batch(
    inner_artifacts: &InnerAggregationArtifacts,
    proofs: Vec<Proof>,
) -> Result<(Proof, StageTiming)> {
    let (session, commit_ms) = time_operation(|| {
        inner_artifacts
            .new_session()
            .commit(InnerAggregationInputs { proofs })
            .context("inner commit failed")
    })?;
    let (proof, prove_ms) = time_operation(|| session.prove().context("inner prove failed"))?;
    Ok((
        proof,
        StageTiming {
            commit_ms,
            prove_ms,
        },
    ))
}

#[cfg(feature = "multithread")]
fn prove_parallel_batches(
    inner_artifacts: &InnerAggregationArtifacts,
    group_a: Vec<Proof>,
    group_b: Vec<Proof>,
) -> Result<(Proof, StageTiming, Proof, StageTiming)> {
    let threads_per_pool = parallel_inner_pool_threads();
    std::thread::scope(|scope| -> Result<_> {
        let a = scope.spawn(|| {
            ThreadPoolBuilder::new()
                .num_threads(threads_per_pool)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build inner A thread pool: {e}"))?
                .install(|| prove_inner_batch(inner_artifacts, group_a))
        });
        let b = scope.spawn(|| {
            ThreadPoolBuilder::new()
                .num_threads(threads_per_pool)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build inner B thread pool: {e}"))?
                .install(|| prove_inner_batch(inner_artifacts, group_b))
        });

        let (proof_a, timing_a) = a
            .join()
            .map_err(|_| anyhow::anyhow!("inner A thread panicked"))?
            .context("inner A failed")?;
        let (proof_b, timing_b) = b
            .join()
            .map_err(|_| anyhow::anyhow!("inner B thread panicked"))?
            .context("inner B failed")?;
        Ok((proof_a, timing_a, proof_b, timing_b))
    })
}

#[cfg(not(feature = "multithread"))]
fn prove_parallel_batches(
    inner_artifacts: &InnerAggregationArtifacts,
    group_a: Vec<Proof>,
    group_b: Vec<Proof>,
) -> Result<(Proof, StageTiming, Proof, StageTiming)> {
    std::thread::scope(|scope| -> Result<_> {
        let a = scope.spawn(|| prove_inner_batch(inner_artifacts, group_a));
        let b = scope.spawn(|| prove_inner_batch(inner_artifacts, group_b));
        let (proof_a, timing_a) = a
            .join()
            .map_err(|_| anyhow::anyhow!("inner A thread panicked"))?
            .context("inner A failed")?;
        let (proof_b, timing_b) = b
            .join()
            .map_err(|_| anyhow::anyhow!("inner B thread panicked"))?
            .context("inner B failed")?;
        Ok((proof_a, timing_a, proof_b, timing_b))
    })
}

#[cfg(feature = "multithread")]
fn parallel_inner_pool_threads() -> usize {
    if let Ok(value) = std::env::var("QP_NONZK_INNER_THREADS") {
        if let Ok(parsed) = value.parse::<usize>() {
            return parsed.max(1);
        }
    }

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let configured = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(available);
    (configured / 2).max(1)
}

fn time_operation<T, O>(op: O) -> Result<(T, f64)>
where
    O: FnOnce() -> Result<T>,
{
    let start = Instant::now();
    let value = op()?;
    Ok((value, start.elapsed().as_secs_f64() * 1000.0))
}

fn load_common_from_bins(bins_dir: &Path, common_file: &str) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;
    let common_bytes = fs::read(bins_dir.join(common_file))
        .with_context(|| format!("failed to read {}", bins_dir.join(common_file).display()))?;
    CommonCircuitData::from_bytes(common_bytes, &gate_serializer)
        .map_err(|e| anyhow::anyhow!("failed to deserialize {}: {}", common_file, e))
}
