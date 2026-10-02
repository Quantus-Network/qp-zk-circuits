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
        }
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
