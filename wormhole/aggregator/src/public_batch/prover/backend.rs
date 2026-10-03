use anyhow::Result;
#[cfg(feature = "gpu")]
use anyhow::{anyhow, Context};
use plonky2::iop::witness::PartialWitness;
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
            Self::Gpu(backend) => backend.prove(circuit, witness),
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
        context: Arc<qp_wormhole_gpu::DeviceContext>,
        options: qp_wormhole_gpu::PreparationOptions,
    ) -> Result<Self> {
        let prepared = qp_wormhole_gpu::PreparedCircuit::prepare_shared(
            &context,
            Arc::clone(&circuit),
            options,
        )
        .context("prepare public-batch GPU circuit")?;
        let workspace = prepared
            .prepare_workspace(&context)
            .context("allocate public-batch GPU workspace")?;
        Ok(Self {
            circuit,
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

    fn prove(
        &self,
        circuit: &Arc<CircuitData<F, C, D>>,
        witness: PartialWitness<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            Arc::ptr_eq(circuit, &self.circuit),
            "public-batch circuit changed after GPU preparation"
        );
        // CPU witness generation does not hold the shared GPU workspace lock.
        let generation = crate::profiling::HostOperation::new("witness_generation");
        let partition = plonky2::iop::generator::generate_partial_witness(
            witness,
            &self.circuit.prover_only,
            &self.circuit.common,
        )
        .context("generate public-batch witness")?;
        drop(generation);
        let lock = crate::profiling::HostOperation::new("workspace_lock_wait");
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|_| anyhow!("public-batch GPU workspace lock was poisoned"))?;
        drop(lock);
        self.prepared
            .prove_with_partition_witness(&self.context, &mut workspace, partition)
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use qp_wormhole_gpu::{DeviceContext, PreparationOptions};

    fn circuit() -> Arc<CircuitData<F, C, D>> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        builder.register_public_input(zero);
        Arc::new(builder.build::<C>())
    }

    #[test]
    fn unavailable_gpu_backend_does_not_fall_back_to_cpu() {
        let backend = ProvingBackend::GpuUnavailable;
        let error = backend
            .prove(&circuit(), PartialWitness::new())
            .unwrap_err();
        assert_eq!(error.to_string(), "GPU backend unavailable; retry with_gpu");
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn gpu_rebuild_releases_old_backend_and_can_retry_after_failure() -> Result<()> {
        let circuit = circuit();
        let options = PreparationOptions::default();
        let old_context = Arc::new(futures::executor::block_on(DeviceContext::new())?);
        let old_weak = Arc::downgrade(&old_context);
        let mut backend = ProvingBackend::Gpu(Box::new(GpuBackend::prepare(
            Arc::clone(&circuit),
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
            GpuBackend::prepare(Arc::clone(&circuit), Arc::clone(&context), options)
        })?;
        let proof = backend.prove(&circuit, PartialWitness::new())?;
        circuit.verify(proof)?;
        Ok(())
    }
}
