#[cfg(feature = "gpu")]
use super::lib::GpuProvingOptions;
#[cfg(feature = "gpu")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "gpu")]
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
#[cfg(feature = "gpu")]
use plonky2::iop::witness::{PartitionWitness, WitnessWrite};
#[cfg(feature = "gpu")]
use plonky2::iop::witness_generation_executor::WitnessGenerationExecutor;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::sync::Arc;
use zk_circuits_common::circuit::{C, D, F};

#[derive(Debug)]
pub(super) enum ProvingBackend {
    Cpu,
    #[cfg(feature = "gpu")]
    Gpu(Box<GpuBackend>),
    #[cfg(feature = "gpu")]
    GpuUnavailable,
}

impl ProvingBackend {
    pub fn prove(
        &self,
        circuit: &Arc<CircuitData<F, C, D>>,
        witness: PartialWitness<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        match self {
            Self::Cpu => {
                #[cfg(feature = "gpu")]
                let _proof = crate::profiling::HostOperation::new("cpu_prove");
                circuit.prove(witness)
            }
            #[cfg(feature = "gpu")]
            Self::Gpu(backend) => {
                anyhow::ensure!(
                    Arc::ptr_eq(circuit, &backend.circuit),
                    "public-batch circuit changed after GPU preparation"
                );
                backend.prove(witness)
            }
            #[cfg(feature = "gpu")]
            Self::GpuUnavailable => anyhow::bail!("GPU backend unavailable; retry with_gpu"),
        }
    }

    #[cfg(feature = "gpu")]
    pub(super) fn replace_gpu(
        &mut self,
        context: &Arc<qp_wormhole_gpu::DeviceContext>,
        prepare: impl FnOnce() -> Result<GpuBackend>,
    ) -> Result<()> {
        if matches!(self, Self::Gpu(_)) {
            let Self::Gpu(old) = std::mem::replace(self, Self::GpuUnavailable) else {
                unreachable!();
            };
            old.release(context)?;
        }
        let backend = prepare()?;
        *self = Self::Gpu(Box::new(backend));
        Ok(())
    }
}

#[cfg(feature = "gpu")]
pub(super) struct GpuBackend {
    circuit: Arc<CircuitData<F, C, D>>,
    witness_executor: std::sync::Mutex<WitnessGenerationExecutor<F>>,
    #[cfg(feature = "gpu-parallel-witness")]
    witness_workers: usize,
    context: Arc<qp_wormhole_gpu::DeviceContext>,
    prepared: qp_wormhole_gpu::PreparedCircuit<'static>,
    workspace: std::sync::Mutex<qp_wormhole_gpu::ProofWorkspace>,
}

#[cfg(feature = "gpu")]
impl std::fmt::Debug for GpuBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuBackend")
            .field("adapter", self.context.adapter_info())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "gpu")]
impl GpuBackend {
    pub fn prepare(
        circuit: Arc<CircuitData<F, C, D>>,
        input_targets: impl IntoIterator<Item = Target>,
        context: Arc<qp_wormhole_gpu::DeviceContext>,
        options: GpuProvingOptions,
    ) -> Result<Self> {
        options.validate()?;
        let witness_executor = WitnessGenerationExecutor::new_with_inputs(&circuit, input_targets)
            .context("prepare public-batch witness executor")?;
        let prepared = qp_wormhole_gpu::PreparedCircuit::prepare_shared(
            &context,
            Arc::clone(&circuit),
            options.preparation,
        )
        .context("prepare public-batch GPU circuit")?;
        let workspace = prepared
            .prepare_workspace(&context)
            .context("allocate public-batch GPU workspace")?;
        Ok(Self {
            circuit,
            witness_executor: std::sync::Mutex::new(witness_executor),
            #[cfg(feature = "gpu-parallel-witness")]
            witness_workers: options.witness_workers,
            context,
            prepared,
            workspace: std::sync::Mutex::new(workspace),
        })
    }

    fn release(self, replacement: &Arc<qp_wormhole_gpu::DeviceContext>) -> Result<()> {
        let Self {
            context,
            prepared,
            workspace,
            ..
        } = self;
        drop(workspace);
        drop(prepared);
        // Process deferred destruction after dropping all backend-owned buffers.
        // A failed old device must not prevent recovery on a fresh context.
        let result = context.wait_idle(std::time::Duration::from_secs(30));
        if Arc::ptr_eq(&context, replacement) {
            result.context("release previous public-batch GPU resources")?;
        }
        Ok(())
    }

    fn prove(&self, witness: PartialWitness<F>) -> Result<ProofWithPublicInputs<F, C, D>> {
        // CPU witness generation does not hold the shared GPU workspace lock.
        let generation = crate::profiling::HostOperation::new("witness_generation");
        let partition = self
            .generate_witness(witness)
            .context("generate public-batch witness")?;
        drop(generation);
        let lock = crate::profiling::HostOperation::new("workspace_lock_wait");
        // A panic in a previous proof leaves no state behind that the next
        // proof depends on: every workspace view is rewritten from scratch.
        let mut workspace = self
            .workspace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(lock);
        self.prepared
            .prove_with_partition_witness(&self.context, &mut workspace, partition)
    }

    fn generate_witness(&self, inputs: PartialWitness<F>) -> Result<PartitionWitness<'_, F>> {
        let mut executor = self
            .witness_executor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut witness = executor.new_witness(&self.circuit);
        for (target, value) in inputs.target_values {
            witness.set_target(target, value)?;
        }
        #[cfg(feature = "gpu-parallel-witness")]
        {
            // SAFETY: Public-batch circuits use built-in generators with complete,
            // stable access sets. Planning and execution use the same unchanged circuit.
            unsafe {
                executor.execute_parallel(&self.circuit, &mut witness, self.witness_workers)?;
            }
        }
        #[cfg(not(feature = "gpu-parallel-witness"))]
        executor.execute(&self.circuit, &mut witness)?;
        Ok(witness)
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use qp_wormhole_gpu::DeviceContext;

    fn build_circuit() -> Arc<CircuitData<F, C, D>> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        builder.register_public_input(zero);
        Arc::new(builder.build::<C>())
    }

    #[test]
    fn unavailable_gpu_backend_does_not_fall_back_to_cpu() {
        let backend = ProvingBackend::GpuUnavailable;
        let error = backend
            .prove(&build_circuit(), PartialWitness::new())
            .unwrap_err();
        assert_eq!(error.to_string(), "GPU backend unavailable; retry with_gpu");
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn gpu_backend_keeps_proving_after_a_worker_panics_mid_proof() -> Result<()> {
        let circuit = build_circuit();
        let context = Arc::new(futures::executor::block_on(DeviceContext::new())?);
        let backend = GpuBackend::prepare(
            Arc::clone(&circuit),
            [],
            context,
            GpuProvingOptions::default(),
        )?;
        circuit.verify(backend.prove(PartialWitness::new())?)?;
        let panicked = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _workspace = backend.workspace.lock().unwrap();
                    panic!("injected panic while holding the workspace");
                })
                .join()
        });
        assert!(panicked.is_err());
        assert!(backend.workspace.is_poisoned());
        circuit.verify(backend.prove(PartialWitness::new())?)?;
        Ok(())
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn gpu_rebuild_releases_old_backend_and_can_retry_after_failure() -> Result<()> {
        let circuit = build_circuit();
        let options = GpuProvingOptions::default();
        let old_context = Arc::new(futures::executor::block_on(DeviceContext::new())?);
        let old_weak = Arc::downgrade(&old_context);
        let mut backend = ProvingBackend::Gpu(Box::new(GpuBackend::prepare(
            Arc::clone(&circuit),
            [],
            old_context,
            options,
        )?));
        let context = Arc::new(futures::executor::block_on(DeviceContext::new())?);
        let error = backend
            .replace_gpu(&context, || {
                // This checks ownership release, not physical driver VRAM reclamation.
                assert!(old_weak.upgrade().is_none());
                anyhow::bail!("injected GPU allocation failure")
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "injected GPU allocation failure");
        assert_eq!(
            backend
                .prove(&circuit, PartialWitness::new())
                .unwrap_err()
                .to_string(),
            "GPU backend unavailable; retry with_gpu"
        );
        backend.replace_gpu(&context, || {
            GpuBackend::prepare(Arc::clone(&circuit), [], Arc::clone(&context), options)
        })?;
        let error = backend
            .prove(&build_circuit(), PartialWitness::new())
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "public-batch circuit changed after GPU preparation"
        );
        let proof = backend.prove(&circuit, PartialWitness::new())?;
        circuit.verify(proof)?;
        Ok(())
    }
}
