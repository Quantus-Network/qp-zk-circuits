use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{ensure, Context, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, Field64, PrimeField64};

static NEXT_DEVICE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_WORKSPACE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_KERNEL_ID: AtomicU64 = AtomicU64::new(1);

/// One hardware device and queue, retained across proofs. No global state or
/// environment variables select the adapter or enable profiling. Uncaptured
/// wgpu errors and device loss invalidate the context; create a new context
/// rather than continuing with potentially invalid resources.
pub struct DeviceContext {
    id: u64,
    info: wgpu::AdapterInfo,
    device: wgpu::Device,
    queue: wgpu::Queue,
    failure: Arc<Mutex<Option<String>>>,
    command_buffers: Option<Arc<MetalCommandBufferPool>>,
}

fn record_failure(failure: &Mutex<Option<String>>, message: String) {
    // Keep the first cause, not a later error from an already-invalid resource.
    failure
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert(message);
}

fn record_gpu_error(failure: &Mutex<Option<String>>, error: wgpu::Error) {
    record_failure(failure, format!("uncaptured wgpu error: {error:#?}"));
}

impl DeviceContext {
    /// Select a hardware adapter. The established kernels require native u64
    /// shader arithmetic; unsupported adapters are rejected, not emulated.
    pub async fn new() -> Result<Self> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: if cfg!(target_os = "macos") {
                wgpu::Backends::METAL
            } else {
                wgpu::Backends::VULKAN
            },
            ..Default::default()
        });
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                force_fallback_adapter: false,
                compatible_surface: None,
            })
            .await
            .context("select GPU adapter")?;
        let info = adapter.get_info();
        ensure!(
            info.device_type != wgpu::DeviceType::Cpu,
            "software adapter is unsupported"
        );
        ensure!(
            adapter.features().contains(wgpu::Features::SHADER_INT64),
            "GPU lacks native u64 shader arithmetic"
        );
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("Wormhole prover"),
                required_features: wgpu::Features::SHADER_INT64,
                required_limits: wgpu::Limits {
                    max_storage_buffer_binding_size: adapter
                        .limits()
                        .max_storage_buffer_binding_size,
                    max_buffer_size: adapter.limits().max_buffer_size,
                    ..wgpu::Limits::default()
                },
                ..Default::default()
            })
            .await
            .context("initialize GPU device")?;
        let failure = Arc::new(Mutex::new(None));
        let callback = Arc::clone(&failure);
        device.set_device_lost_callback(move |reason, message| {
            record_failure(&callback, format!("device lost: {reason:?}: {message}"));
        });
        let callback = Arc::clone(&failure);
        device.on_uncaptured_error(Arc::new(move |error| {
            record_gpu_error(&callback, error);
        }));
        let command_buffers = (info.backend == wgpu::Backend::Metal)
            .then(|| Arc::new(MetalCommandBufferPool::new(METAL_COMMAND_BUFFERS)));
        let context = Self {
            id: NEXT_DEVICE_ID.fetch_add(1, Ordering::Relaxed),
            info,
            device,
            queue,
            failure,
            command_buffers,
        };
        context.check_device()?;
        Ok(context)
    }

    pub fn adapter_info(&self) -> &wgpu::AdapterInfo {
        &self.info
    }

    pub fn limits(&self) -> wgpu::Limits {
        self.device.limits()
    }

    fn check_device(&self) -> Result<()> {
        let failure = self.failure.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            failure.is_none(),
            "GPU context failed: {}",
            failure.as_deref().unwrap_or("")
        );
        Ok(())
    }

    fn validate_source(&self, source: FieldSource<'_>) -> Result<()> {
        self.check_device()?;
        ensure!(
            source.device_id() == self.id,
            "buffer belongs to another GPU device"
        );
        Ok(())
    }

    /// Initialize immutable field data during circuit preparation. The returned
    /// view is shared across workspaces and has no upload/write API. Its backing
    /// allocation permits storage reads and debug export, but not copy writes.
    pub fn prepare_fixed(&self, values: &[GoldilocksField]) -> Result<FixedFieldSlice> {
        self.check_device()?;
        let size = field_bytes(values.len())?;
        let limits = self.limits();
        ensure!(
            size > 0
                && size <= limits.max_buffer_size
                && size <= u64::from(limits.max_storage_buffer_binding_size),
            "fixed field buffer exceeds device limits"
        );
        let buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("fixed circuit field buffer"),
            size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: true,
        });
        self.check_device()?;
        {
            let mut mapped = buffer.slice(..).get_mapped_range_mut();
            for (value, bytes) in values.iter().zip(mapped.chunks_exact_mut(8)) {
                bytes.copy_from_slice(&value.to_canonical_u64().to_le_bytes());
            }
        }
        buffer.unmap();
        self.check_device()?;
        Ok(FixedFieldSlice {
            device_id: self.id,
            buffer,
            offset: 0,
            len: values.len(),
        })
    }

    pub(crate) fn prepare_params<const N: usize>(&self, values: [u32; N]) -> Result<KernelParams> {
        self.check_device()?;
        let size = N.checked_mul(4).context("kernel parameter size overflow")?;
        ensure!(
            N > 0
                && N.is_multiple_of(4)
                && size <= self.limits().max_uniform_buffer_binding_size as usize,
            "invalid kernel parameter size"
        );
        let buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("prepared kernel parameters"),
            size: size as u64,
            usage: wgpu::BufferUsages::UNIFORM,
            mapped_at_creation: true,
        });
        self.check_device()?;
        {
            let mut mapped = buffer.slice(..).get_mapped_range_mut();
            for (value, bytes) in values.iter().zip(mapped.chunks_exact_mut(4)) {
                bytes.copy_from_slice(&value.to_le_bytes());
            }
        }
        buffer.unmap();
        self.check_device()?;
        Ok(KernelParams {
            device_id: self.id,
            buffer,
        })
    }

    /// Explicit export boundary. Copies only the requested view, then waits for
    /// mapping. Proof encoding and submission never call this method.
    pub fn readback<'a>(&self, source: impl Into<FieldSource<'a>>) -> Result<Vec<GoldilocksField>> {
        let source = source.into();
        self.validate_source(source)?;
        let (buffer, offset, len) = source.parts();
        let bytes = field_bytes(len)?;
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("field export"),
            size: bytes,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        // Reclaim completed reservations before checking queue capacity; do not wait.
        self.device
            .poll(wgpu::PollType::Poll)
            .context("poll completed work before field export")?;
        self.check_device()?;
        let mut command_budget = MetalCommandBufferBudget::new(self.command_buffers.clone())?;
        command_budget.copy()?;
        let mut encoder = self.device.create_command_encoder(&Default::default());
        encoder.copy_buffer_to_buffer(buffer, offset, &staging, 0, bytes);
        let commands = encoder.finish();
        if let Err(error) = self.check_device() {
            drop(commands);
            return Err(error);
        }
        self.queue.submit([commands]);
        self.queue
            .on_submitted_work_done(move || drop(command_budget));
        self.check_device()?;
        let (tx, rx) = std::sync::mpsc::channel();
        staging
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |result| {
                let _ = tx.send(result);
            });
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .context("wait for field export")?;
        self.check_device()?;
        rx.recv().context("receive field export completion")??;
        let mapped = staging.slice(..).get_mapped_range();
        let values = mapped
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        drop(mapped);
        staging.unmap();
        ensure!(
            values.iter().all(|value| *value < GoldilocksField::ORDER),
            "GPU exported noncanonical field value"
        );
        Ok(values
            .into_iter()
            .map(GoldilocksField::from_canonical_u64)
            .collect())
    }
}

/// Shared immutable canonical Goldilocks data, normally owned by a prepared
/// circuit. Clones and subviews pin the entire backing allocation. No write
/// method accepts this type, and kernels bind it as read-only storage.
#[derive(Clone)]
pub struct FixedFieldSlice {
    device_id: u64,
    buffer: wgpu::Buffer,
    offset: u64,
    len: usize,
}

impl FixedFieldSlice {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn slice(&self, range: Range<usize>) -> Result<Self> {
        let (offset, len) = field_range(self.offset, self.len, range)?;
        Ok(Self {
            offset,
            len,
            ..self.clone()
        })
    }
}

/// Read access to either immutable circuit data or mutable workspace data.
/// This type is never accepted as a write destination.
#[derive(Clone, Copy)]
pub enum FieldSource<'a> {
    Fixed(&'a FixedFieldSlice),
    Workspace(&'a DeviceFieldSlice),
}

impl<'a> From<&'a FixedFieldSlice> for FieldSource<'a> {
    fn from(slice: &'a FixedFieldSlice) -> Self {
        Self::Fixed(slice)
    }
}

impl<'a> From<&'a DeviceFieldSlice> for FieldSource<'a> {
    fn from(slice: &'a DeviceFieldSlice) -> Self {
        Self::Workspace(slice)
    }
}

impl<'a> FieldSource<'a> {
    pub fn len(self) -> usize {
        self.parts().2
    }
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
    fn device_id(self) -> u64 {
        match self {
            Self::Fixed(slice) => slice.device_id,
            Self::Workspace(slice) => slice.device_id,
        }
    }

    fn parts(self) -> (&'a wgpu::Buffer, u64, usize) {
        match self {
            Self::Fixed(slice) => (&slice.buffer, slice.offset, slice.len),
            Self::Workspace(slice) => (&slice.buffer, slice.offset, slice.len),
        }
    }
}

/// A view of canonical Goldilocks values (eight bytes each). Cloning or slicing
/// creates no allocation or copy. Writes are restricted to its workspace lease.
/// Views own cloned buffer handles: they keep the entire backing allocation
/// alive even after the workspace is dropped. Drop all views to release it.
#[derive(Clone)]
pub struct DeviceFieldSlice {
    device_id: u64,
    workspace_id: u64,
    buffer: wgpu::Buffer,
    offset: u64,
    len: usize,
}

impl DeviceFieldSlice {
    pub(crate) fn shares_buffer(&self, other: &Self) -> bool {
        self.buffer == other.buffer
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn slice(&self, range: Range<usize>) -> Result<Self> {
        let (offset, len) = field_range(self.offset, self.len, range)?;
        Ok(Self {
            offset,
            len,
            ..self.clone()
        })
    }
}

fn field_range(offset: u64, len: usize, range: Range<usize>) -> Result<(u64, usize)> {
    ensure!(
        range.start < range.end && range.end <= len,
        "invalid field slice range"
    );
    Ok((
        offset
            .checked_add(field_bytes(range.start)?)
            .context("field slice offset overflow")?,
        range.end - range.start,
    ))
}

fn field_bytes(len: usize) -> Result<u64> {
    u64::try_from(len)?
        .checked_mul(8)
        .context("field buffer size overflow")
}

/// Storage access declared during kernel preparation, not inferred from a
/// caller's bind group. Layout and shader compatibility are checked by wgpu.
#[allow(dead_code)] // Used by the forthcoming mathematical operations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingAccess {
    Read,
    ReadWrite,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct FieldBindingSpec {
    pub access: BindingAccess,
    pub min_elements: usize,
}

/// Writable bindings cannot contain a FixedFieldSlice, even before validation.
#[allow(dead_code)]
pub(crate) enum FieldBinding<'a> {
    Read(FieldSource<'a>),
    ReadWrite(&'a DeviceFieldSlice),
}

/// A pipeline and its explicit storage access contract, created at initialization.
/// Raw pipelines and bind groups never reach the proof dispatch interface.
#[allow(dead_code)]
pub(crate) struct PreparedKernel {
    id: u64,
    device_id: u64,
    pipeline: wgpu::ComputePipeline,
    layout: wgpu::BindGroupLayout,
    specs: Vec<FieldBindingSpec>,
    params_bytes: u64,
}

/// Immutable host-known dispatch metadata, prepared outside proof encoding.
pub(crate) struct KernelParams {
    device_id: u64,
    buffer: wgpu::Buffer,
}

#[allow(dead_code)]
impl PreparedKernel {
    pub fn prepare(
        context: &DeviceContext,
        source: &str,
        specs: &[FieldBindingSpec],
        label: &str,
    ) -> Result<Self> {
        Self::prepare_entry(context, source, specs, label, "main", false)
    }

    pub fn prepare_entry(
        context: &DeviceContext,
        source: &str,
        specs: &[FieldBindingSpec],
        label: &str,
        entry: &str,
        has_params: bool,
    ) -> Result<Self> {
        Self::prepare_entry_with_params(
            context,
            source,
            specs,
            label,
            entry,
            if has_params { 4 } else { 0 },
        )
    }

    pub fn prepare_entry_with_params(
        context: &DeviceContext,
        source: &str,
        specs: &[FieldBindingSpec],
        label: &str,
        entry: &str,
        param_words: usize,
    ) -> Result<Self> {
        context.check_device()?;
        let limits = context.limits();
        let params_bytes = param_words
            .checked_mul(4)
            .context("kernel parameter size overflow")? as u64;
        ensure!(
            param_words.is_multiple_of(4)
                && params_bytes <= u64::from(limits.max_uniform_buffer_binding_size),
            "invalid kernel parameter size"
        );
        let has_params = params_bytes > 0;
        ensure!(
            specs.len() <= limits.max_storage_buffers_per_shader_stage as usize
                && specs.len() + usize::from(has_params)
                    <= limits.max_bindings_per_bind_group as usize,
            "too many kernel field bindings"
        );
        let mut entries = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                let bytes = field_bytes(spec.min_elements)?;
                ensure!(
                    bytes > 0 && bytes <= u64::from(limits.max_storage_buffer_binding_size),
                    "invalid kernel minimum binding size"
                );
                Ok(wgpu::BindGroupLayoutEntry {
                    binding: u32::try_from(index)?,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage {
                            read_only: spec.access == BindingAccess::Read,
                        },
                        has_dynamic_offset: false,
                        min_binding_size: wgpu::BufferSize::new(bytes),
                    },
                    count: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if has_params {
            entries.push(wgpu::BindGroupLayoutEntry {
                binding: u32::try_from(specs.len())?,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: wgpu::BufferSize::new(params_bytes),
                },
                count: None,
            });
        }
        let layout = context
            .device
            .create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some(label),
                entries: &entries,
            });
        context.check_device()?;
        let pipeline_layout =
            context
                .device
                .create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                    label: Some(label),
                    bind_group_layouts: &[&layout],
                    push_constant_ranges: &[],
                });
        context.check_device()?;
        let module = context
            .device
            .create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some(label),
                source: wgpu::ShaderSource::Wgsl(source.into()),
            });
        context.check_device()?;
        let pipeline = context
            .device
            .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some(label),
                layout: Some(&pipeline_layout),
                module: &module,
                entry_point: Some(entry),
                compilation_options: Default::default(),
                cache: None,
            });
        context.check_device()?;
        Ok(Self {
            id: NEXT_KERNEL_ID.fetch_add(1, Ordering::Relaxed),
            device_id: context.id,
            pipeline,
            layout,
            specs: specs.to_vec(),
            params_bytes,
        })
    }
}

/// Constructed only by the owning encoder after validating every binding.
#[allow(dead_code)]
pub(crate) struct CheckedBindings {
    device_id: u64,
    workspace_id: u64,
    kernel_id: u64,
    group: wgpu::BindGroup,
}

fn validate_binding_range(
    offset: u64,
    len: usize,
    buffer_bytes: u64,
    minimum: usize,
    limits: &wgpu::Limits,
) -> Result<()> {
    ensure!(
        len > 0 && len >= minimum,
        "field binding is smaller than the kernel requires"
    );
    ensure!(
        offset.is_multiple_of(u64::from(limits.min_storage_buffer_offset_alignment)),
        "field binding offset is not storage-aligned"
    );
    let bytes = field_bytes(len)?;
    ensure!(
        bytes <= u64::from(limits.max_storage_buffer_binding_size),
        "field binding exceeds storage limit"
    );
    ensure!(
        offset
            .checked_add(bytes)
            .is_some_and(|end| end <= buffer_bytes),
        "field binding exceeds backing allocation"
    );
    Ok(())
}

enum Completion {
    Ready,
    Pending(Arc<AtomicBool>),
    Poisoned,
}

impl Completion {
    fn reclaim(&mut self) -> Result<()> {
        match self {
            Self::Ready => Ok(()),
            Self::Pending(done) if done.load(Ordering::Acquire) => {
                *self = Self::Ready;
                Ok(())
            }
            Self::Pending(_) => anyhow::bail!("proof workspace is still in use by the GPU"),
            Self::Poisoned => anyhow::bail!("proof workspace was invalidated by device failure"),
        }
    }
}

/// Per-proof mutable buffers, allocated once from an explicit size plan.
/// Multiple proofs require separate workspaces, not shared mutable scratch.
/// Dropping the workspace does not free allocations still held by field slices.
pub struct ProofWorkspace {
    device_id: u64,
    id: u64,
    buffers: Vec<DeviceFieldSlice>,
    allocated_bytes: u64,
    completion: Completion,
}

impl ProofWorkspace {
    pub fn prepare(context: &DeviceContext, field_counts: &[usize]) -> Result<Self> {
        context.check_device()?;
        let limits = context.limits();
        // Validate the entire plan before allocating any of it.
        let sizes = field_counts
            .iter()
            .map(|&len| {
                let bytes = field_bytes(len)?;
                ensure!(
                    bytes > 0
                        && bytes <= limits.max_buffer_size
                        && bytes <= u64::from(limits.max_storage_buffer_binding_size),
                    "field buffer exceeds device limits"
                );
                Ok(bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        let allocated_bytes = sizes.iter().try_fold(0u64, |sum, bytes| {
            sum.checked_add(*bytes).context("workspace size overflow")
        })?;
        let id = NEXT_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
        let buffers = field_counts
            .iter()
            .zip(sizes)
            .map(|(&len, size)| {
                let buffer = context.device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("proof field buffer"),
                    size,
                    usage: wgpu::BufferUsages::STORAGE
                        | wgpu::BufferUsages::COPY_SRC
                        | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                });
                context
                    .check_device()
                    .context("allocate proof field buffer")?;
                Ok(DeviceFieldSlice {
                    device_id: context.id,
                    workspace_id: id,
                    offset: 0,
                    len,
                    buffer,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            device_id: context.id,
            id,
            buffers,
            allocated_bytes,
            completion: Completion::Ready,
        })
    }

    /// Planned buffer bytes only; not a measurement of total VRAM usage.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    pub fn buffer(&self, index: usize) -> Result<DeviceFieldSlice> {
        self.buffers
            .get(index)
            .cloned()
            .context("invalid workspace buffer index")
    }

    /// Explicitly wait for reuse after dropping a submission token. This waits
    /// for the device queue; begin() remains nonblocking. Failures poison the
    /// workspace and cannot be cleared by a completion callback.
    pub fn wait(&mut self, context: &DeviceContext) -> Result<()> {
        ensure!(
            self.device_id == context.id,
            "workspace belongs to another GPU device"
        );
        ensure!(
            !matches!(self.completion, Completion::Poisoned),
            "proof workspace was invalidated by device failure"
        );
        if let Err(error) = context.check_device().and_then(|_| {
            if matches!(self.completion, Completion::Pending(_)) {
                context
                    .device
                    .poll(wgpu::PollType::wait_indefinitely())
                    .context("wait for proof workspace")?;
            }
            context.check_device()
        }) {
            self.completion = Completion::Poisoned;
            return Err(error);
        }
        self.completion.reclaim()
    }

    pub fn begin<'a>(&'a mut self, context: &'a DeviceContext) -> Result<ProofEncoder<'a>> {
        ensure!(
            self.device_id == context.id,
            "workspace belongs to another GPU device"
        );
        if let Err(error) = context.check_device().and_then(|_| {
            context.device.poll(wgpu::PollType::Poll)?;
            context.check_device()
        }) {
            self.completion = Completion::Poisoned;
            return Err(error);
        }
        self.completion.reclaim()?;
        let command_budget = MetalCommandBufferBudget::new(context.command_buffers.clone())?;
        let commands = context.device.create_command_encoder(&Default::default());
        context.check_device()?;
        Ok(ProofEncoder {
            context,
            commands,
            workspace: self,
            command_budget,
        })
    }
}

/// An exclusive workspace lease. All writes, copies and dispatches are queued
/// in one command encoder; dropping it before submission discards them all.
/// Excessive command fragmentation on Metal returns an error before submission;
/// use larger row chunks or submit separate stage encoders in that case.
pub struct ProofEncoder<'a> {
    context: &'a DeviceContext,
    workspace: &'a mut ProofWorkspace,
    commands: wgpu::CommandEncoder,
    // Drop the native encoder before releasing its reservation on cancellation.
    command_budget: MetalCommandBufferBudget,
}

// wgpu-hal 27's Metal queue permits 4096 outstanding native command buffers.
// wgpu-core 27 records two per compute pass, plus one per contiguous copy run.
// Reserve four per encoder for initialization/submission work. wgpu-core 27
// materializes recorded passes at finish(), so reserve before recording and
// retain capacity across all encoders until cancellation or GPU completion.
// Other backends do not have this particular queue limit.
const METAL_COMMAND_BUFFERS: usize = 4096;
const SUBMISSION_OVERHEAD: usize = 4;

struct MetalCommandBufferPool {
    used: AtomicUsize,
    limit: usize,
}

impl MetalCommandBufferPool {
    fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    fn reserve(&self, count: usize) -> Result<()> {
        ensure!(self.used.fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            used.checked_add(count).filter(|&next| next <= self.limit)
        }).is_ok(),
            "Metal command-buffer capacity is in use; finish outstanding work or drop unsubmitted encoders");
        Ok(())
    }
}

struct MetalCommandBufferBudget {
    pool: Option<Arc<MetalCommandBufferPool>>,
    used: usize,
    copying: bool,
}

impl MetalCommandBufferBudget {
    fn new(pool: Option<Arc<MetalCommandBufferPool>>) -> Result<Self> {
        let mut budget = Self {
            pool,
            used: 0,
            copying: false,
        };
        budget.reserve(SUBMISSION_OVERHEAD)?;
        Ok(budget)
    }

    fn reserve(&mut self, count: usize) -> Result<()> {
        if let Some(pool) = &self.pool {
            let used = self
                .used
                .checked_add(count)
                .context("command count overflow")?;
            ensure!(used <= METAL_COMMAND_BUFFERS,
                "Metal command-buffer limit exceeded; use larger row chunks or separate submissions");
            pool.reserve(count)?;
            self.used = used;
        }
        Ok(())
    }

    fn copy(&mut self) -> Result<()> {
        self.reserve(usize::from(!self.copying))?;
        self.copying = true;
        Ok(())
    }

    fn dispatch(&mut self) -> Result<()> {
        self.reserve(2)?;
        self.copying = false;
        Ok(())
    }
}

impl Drop for MetalCommandBufferBudget {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            pool.used.fetch_sub(self.used, Ordering::AcqRel);
        }
    }
}

impl ProofEncoder<'_> {
    fn validate(&self, slice: &DeviceFieldSlice) -> Result<()> {
        self.context.validate_source(slice.into())?;
        ensure!(
            slice.workspace_id == self.workspace.id,
            "buffer belongs to another proof workspace"
        );
        Ok(())
    }

    fn validate_source(&self, source: FieldSource<'_>) -> Result<()> {
        match source {
            FieldSource::Fixed(_) => self.context.validate_source(source),
            FieldSource::Workspace(slice) => self.validate(slice),
        }
    }

    /// Encode upload rather than queue.write_buffer: cancellation before submit
    /// must not mutate buffers that the next proof will reuse.
    /// Fixed circuit data cannot be overwritten through this API:
    /// ```compile_fail
    /// use qp_wormhole_gpu::{FixedFieldSlice, ProofEncoder};
    /// fn overwrite(encoder: &mut ProofEncoder<'_>, fixed: &FixedFieldSlice) {
    ///     encoder.upload(fixed, &[]).unwrap();
    /// }
    /// ```
    pub fn upload(
        &mut self,
        destination: &DeviceFieldSlice,
        values: &[GoldilocksField],
    ) -> Result<()> {
        self.validate(destination)?;
        ensure!(destination.len == values.len(), "upload length mismatch");
        self.command_budget.copy()?;
        let bytes = values
            .iter()
            .flat_map(|value| value.to_canonical_u64().to_le_bytes())
            .collect::<Vec<_>>();
        // Do not use create_buffer_init: it maps immediately after allocation,
        // before we can reject an allocation failure and its invalid handle.
        let staging = self.context.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("field upload"),
            size: bytes.len() as u64,
            usage: wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: true,
        });
        self.context.check_device()?;
        staging
            .slice(..)
            .get_mapped_range_mut()
            .copy_from_slice(&bytes);
        staging.unmap();
        self.context.check_device()?;
        self.commands.copy_buffer_to_buffer(
            &staging,
            0,
            &destination.buffer,
            destination.offset,
            bytes.len() as u64,
        );
        self.context.check_device()
    }

    /// Sources may be fixed or workspace-owned; destinations must be mutable.
    /// ```compile_fail
    /// use qp_wormhole_gpu::{DeviceFieldSlice, FixedFieldSlice, ProofEncoder};
    /// fn overwrite(encoder: &mut ProofEncoder<'_>, source: &DeviceFieldSlice, fixed: &FixedFieldSlice) {
    ///     encoder.copy(source, fixed).unwrap();
    /// }
    /// ```
    pub fn copy<'a>(
        &mut self,
        source: impl Into<FieldSource<'a>>,
        destination: &DeviceFieldSlice,
    ) -> Result<()> {
        let source = source.into();
        self.validate_source(source)?;
        self.validate(destination)?;
        let (buffer, offset, len) = source.parts();
        ensure!(len == destination.len, "field copy length mismatch");
        ensure!(
            *buffer != destination.buffer,
            "same-buffer copies are unsupported"
        );
        self.command_budget.copy()?;
        self.commands.copy_buffer_to_buffer(
            buffer,
            offset,
            &destination.buffer,
            destination.offset,
            field_bytes(len)?,
        );
        self.context.check_device()
    }

    /// Bind field buffers through the prepared kernel's access contract. Fixed
    /// sources can only occupy Read slots, whose layouts are read-only storage.
    /// Mutable sources and destinations must belong to this workspace.
    /// Subview offsets must meet the device's min_storage_buffer_offset_alignment
    /// (typically 256 bytes / 32 fields); copies need only copy alignment.
    /// A backing buffer cannot occupy both Read and ReadWrite slots, even for
    /// disjoint subviews: wgpu tracks storage usage per buffer, not per range.
    #[allow(dead_code)] // Used by the next mathematical-operations stage.
    pub(crate) fn bind(
        &self,
        kernel: &PreparedKernel,
        bindings: &[FieldBinding<'_>],
        label: &str,
    ) -> Result<CheckedBindings> {
        self.bind_with_params(kernel, bindings, None, label)
    }

    pub(crate) fn bind_with_params(
        &self,
        kernel: &PreparedKernel,
        bindings: &[FieldBinding<'_>],
        params: Option<&KernelParams>,
        label: &str,
    ) -> Result<CheckedBindings> {
        self.context.check_device()?;
        ensure!(
            kernel.device_id == self.context.id,
            "kernel belongs to another GPU device"
        );
        ensure!(
            bindings.len() == kernel.specs.len(),
            "kernel binding count mismatch"
        );
        ensure!(
            params.is_some() == (kernel.params_bytes > 0),
            "kernel parameter binding mismatch"
        );
        if let Some(params) = params {
            ensure!(
                params.buffer.size() == kernel.params_bytes,
                "kernel parameter size mismatch"
            );
            ensure!(
                params.device_id == self.context.id,
                "kernel parameters belong to another GPU device"
            );
        }
        let limits = self.context.limits();
        let mut entries = bindings
            .iter()
            .zip(&kernel.specs)
            .enumerate()
            .map(|(index, (binding, spec))| {
                let source = match (binding, spec.access) {
                    (FieldBinding::Read(source), BindingAccess::Read) => *source,
                    (FieldBinding::ReadWrite(slice), BindingAccess::ReadWrite) => {
                        FieldSource::Workspace(slice)
                    }
                    _ => anyhow::bail!("kernel binding access mismatch"),
                };
                self.validate_source(source)?;
                let (buffer, offset, len) = source.parts();
                validate_binding_range(offset, len, buffer.size(), spec.min_elements, &limits)?;
                Ok(wgpu::BindGroupEntry {
                    binding: u32::try_from(index)?,
                    resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                        buffer,
                        offset,
                        size: wgpu::BufferSize::new(field_bytes(len)?),
                    }),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let writable = bindings
            .iter()
            .filter_map(|binding| match binding {
                FieldBinding::ReadWrite(slice) => Some(&slice.buffer),
                FieldBinding::Read(_) => None,
            })
            .collect::<Vec<_>>();
        for binding in bindings {
            if let FieldBinding::Read(source) = binding {
                let (buffer, _, _) = source.parts();
                ensure!(
                    !writable.contains(&buffer),
                    "buffer cannot be both read-only and writable in one dispatch"
                );
            }
        }
        if let Some(params) = params {
            entries.push(wgpu::BindGroupEntry {
                binding: u32::try_from(bindings.len())?,
                resource: params.buffer.as_entire_binding(),
            });
        }
        let group = self
            .context
            .device
            .create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some(label),
                layout: &kernel.layout,
                entries: &entries,
            });
        self.context.check_device()?;
        Ok(CheckedBindings {
            device_id: self.context.id,
            workspace_id: self.workspace.id,
            kernel_id: kernel.id,
            group,
        })
    }

    pub(crate) fn dispatch(
        &mut self,
        kernel: &PreparedKernel,
        bindings: &CheckedBindings,
        workgroups: [u32; 3],
        label: &str,
    ) -> Result<()> {
        self.context.check_device()?;
        ensure!(
            kernel.device_id == self.context.id && bindings.device_id == self.context.id,
            "dispatch resources belong to another GPU device"
        );
        ensure!(
            bindings.workspace_id == self.workspace.id,
            "bindings belong to another proof workspace"
        );
        ensure!(
            bindings.kernel_id == kernel.id,
            "bindings belong to another kernel"
        );
        ensure!(
            workgroups
                .iter()
                .all(|&n| n > 0 && n <= self.context.limits().max_compute_workgroups_per_dimension),
            "invalid compute dispatch dimensions"
        );
        self.command_budget.dispatch()?;
        let mut pass = self
            .commands
            .begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some(label),
                timestamp_writes: None,
            });
        pass.set_pipeline(&kernel.pipeline);
        pass.set_bind_group(0, &bindings.group, &[]);
        pass.dispatch_workgroups(workgroups[0], workgroups[1], workgroups[2]);
        drop(pass);
        self.context.check_device()
    }

    pub(crate) fn dispatch_elements(
        &mut self,
        kernel: &PreparedKernel,
        bindings: &CheckedBindings,
        elements: usize,
        label: &str,
    ) -> Result<()> {
        let groups = u32::try_from(elements.div_ceil(64))?;
        ensure!(groups > 0, "empty compute dispatch");
        // Shader row addressing uses a fixed 2^21-element stride per y row.
        self.dispatch(
            kernel,
            bindings,
            [groups.min(32768), groups.div_ceil(32768), 1],
            label,
        )
    }
}

impl<'a> ProofEncoder<'a> {
    /// Submit without a GPU wait or readback. A dropped completion token does
    /// not release the workspace until its GPU completion callback fires.
    pub fn submit(self) -> Result<PendingSubmission<'a>> {
        self.context.check_device()?;
        let Self {
            context,
            workspace,
            commands,
            command_budget,
        } = self;
        let commands = commands.finish();
        if let Err(error) = context.check_device() {
            drop(commands);
            return Err(error);
        }
        context.queue.submit([commands]);
        let done = Arc::new(AtomicBool::new(false));
        let callback = Arc::clone(&done);
        context.queue.on_submitted_work_done(move || {
            drop(command_budget);
            callback.store(true, Ordering::Release);
        });
        workspace.completion = Completion::Pending(done);
        if let Err(error) = context.check_device() {
            workspace.completion = Completion::Poisoned;
            return Err(error);
        }
        Ok(PendingSubmission { context, workspace })
    }
}

pub struct PendingSubmission<'a> {
    context: &'a DeviceContext,
    workspace: &'a mut ProofWorkspace,
}

impl PendingSubmission<'_> {
    /// Explicit finalization wait, separate from proof command submission.
    pub fn finish(self) -> Result<()> {
        self.workspace.wait(self.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metal_command_budget_counts_passes_and_copy_runs() -> Result<()> {
        let pool = Arc::new(MetalCommandBufferPool::new(METAL_COMMAND_BUFFERS));
        let mut budget = MetalCommandBufferBudget::new(Some(pool.clone()))?;
        for _ in 0..10000 {
            budget.copy()?;
        }
        assert_eq!(budget.used, SUBMISSION_OVERHEAD + 1);
        budget.dispatch()?;
        budget.copy()?;
        assert_eq!(budget.used, SUBMISSION_OVERHEAD + 4);
        for _ in 0..(METAL_COMMAND_BUFFERS - SUBMISSION_OVERHEAD - 4) / 2 {
            budget.dispatch()?;
        }
        let before = budget.used;
        assert_eq!(
            budget.dispatch().unwrap_err().to_string(),
            "Metal command-buffer limit exceeded; use larger row chunks or separate submissions"
        );
        assert_eq!(budget.used, before);
        assert_eq!(pool.used.load(Ordering::Acquire), before);
        drop(budget);
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        let mut other = MetalCommandBufferBudget::new(None)?;
        for _ in 0..METAL_COMMAND_BUFFERS {
            other.dispatch()?;
            other.copy()?;
        }
        Ok(())
    }

    #[test]
    fn metal_command_capacity_is_shared_until_cancel_or_completion() -> Result<()> {
        let pool = Arc::new(MetalCommandBufferPool::new(16));
        let mut first = MetalCommandBufferBudget::new(Some(pool.clone()))?;
        first.reserve(8)?;
        let mut second = MetalCommandBufferBudget::new(Some(pool.clone()))?;
        assert_eq!(pool.used.load(Ordering::Acquire), 16);
        let shared_error = "Metal command-buffer capacity is in use; finish outstanding work or drop unsubmitted encoders";
        assert_eq!(second.copy().unwrap_err().to_string(), shared_error);
        assert_eq!(second.used, SUBMISSION_OVERHEAD);
        assert!(!second.copying);
        assert!(MetalCommandBufferBudget::new(Some(pool.clone())).is_err());
        assert_eq!(pool.used.load(Ordering::Acquire), 16);
        // Cancellation releases only the cancelled encoder's reservation.
        drop(first);
        second.copy()?;
        assert_eq!(pool.used.load(Ordering::Acquire), 5);
        // Transfer ownership as submit() does: no release until the callback.
        let complete = move || drop(second);
        let mut third = MetalCommandBufferBudget::new(Some(pool.clone()))?;
        assert_eq!(third.reserve(8).unwrap_err().to_string(), shared_error);
        complete();
        third.reserve(8)?;
        drop(third);
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn metal_command_reservations_are_atomic_between_encoders() -> Result<()> {
        let pool = Arc::new(MetalCommandBufferPool::new(12));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let pool = pool.clone();
                let barrier = barrier.clone();
                workers.push(scope.spawn(move || -> Result<()> {
                    let mut budget = MetalCommandBufferBudget::new(Some(pool))?;
                    budget.dispatch()?;
                    barrier.wait();
                    assert!(budget.copy().is_err());
                    barrier.wait();
                    Ok(())
                }));
            }
            barrier.wait();
            assert_eq!(pool.used.load(Ordering::Acquire), 12);
            barrier.wait();
            for worker in workers {
                worker.join().unwrap()?;
            }
            Ok::<_, anyhow::Error>(())
        })?;
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn buffer_sizes_are_checked() {
        assert_eq!(field_bytes(53).unwrap(), 424);
        assert!(field_bytes(usize::MAX).is_err());
        assert_eq!(field_range(8, 4, 1..3).unwrap(), (16, 2));
        assert!(field_range(u64::MAX - 4, 4, 1..3).is_err());
    }

    #[test]
    fn binding_ranges_require_alignment_size_and_bounds() {
        let limits = wgpu::Limits::default();
        let alignment = u64::from(limits.min_storage_buffer_offset_alignment);
        assert!(validate_binding_range(alignment, 2, alignment + 16, 2, &limits).is_ok());
        assert!(validate_binding_range(8, 2, 64, 2, &limits).is_err());
        assert!(validate_binding_range(0, 1, 16, 2, &limits).is_err());
        assert!(validate_binding_range(0, 2, 8, 2, &limits).is_err());
        assert!(validate_binding_range(0, 0, 8, 0, &limits).is_err());
        assert!(validate_binding_range(0, usize::MAX, u64::MAX, 1, &limits).is_err());
    }

    #[test]
    fn first_failure_is_retained() {
        let failure = Mutex::new(None);
        // Exercise the same handler as the device callback without deliberately
        // exhausting VRAM. Real callback installation is checked on hardware.
        record_gpu_error(
            &failure,
            wgpu::Error::OutOfMemory {
                source: Box::new(std::io::Error::other("injected allocation failure")),
            },
        );
        let first = failure.lock().unwrap().clone();
        assert!(first.as_deref().unwrap().contains("OutOfMemory"));
        assert!(first
            .as_deref()
            .unwrap()
            .contains("injected allocation failure"));
        record_failure(&failure, "invalid buffer after allocation failure".into());
        assert_eq!(*failure.lock().unwrap(), first);
    }

    #[test]
    fn cancellation_does_not_release_pending_work() {
        let done = Arc::new(AtomicBool::new(false));
        let mut state = Completion::Pending(Arc::clone(&done));
        assert!(state.reclaim().is_err());
        done.store(true, Ordering::Release);
        state.reclaim().unwrap();
        let next = Arc::new(AtomicBool::new(false));
        state = Completion::Pending(next);
        assert!(state.reclaim().is_err());
        state = Completion::Poisoned;
        assert!(state.reclaim().is_err());
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn hardware_upload_copy_export_and_reuse() -> Result<()> {
        let mut context = futures::executor::block_on(DeviceContext::new())?;
        let mut workspace = ProofWorkspace::prepare(&context, &[4, 2])?;
        assert_eq!(workspace.allocated_bytes(), 48);
        let source = workspace.buffer(0)?;
        let destination = workspace.buffer(1)?;
        assert!(source.slice(3..5).is_err());
        assert!(ProofWorkspace::prepare(&context, &[0]).is_err());
        let mut other = ProofWorkspace::prepare(&context, &[2])?;
        let foreign = other.buffer(0)?;
        // Prepare the tiny test pipeline once, before any proof encoding.
        // This is an execution oracle, not a production arithmetic kernel.
        let kernel = PreparedKernel::prepare(&context,
            "@group(0) @binding(0) var<storage, read_write> values: array<u64>;\n@compute @workgroup_size(1) fn main(@builtin(global_invocation_id) id: vec3<u32>) { values[id.x] = values[id.x] + 1lu; }",
            &[FieldBindingSpec { access: BindingAccess::ReadWrite, min_elements: 2 }], "execution test")?;
        for start in [0, 10] {
            let values = (start..start + 4)
                .map(GoldilocksField::from_canonical_u64)
                .collect::<Vec<_>>();
            let mut encoder = workspace.begin(&context)?;
            assert!(encoder.copy(&foreign, &destination).is_err());
            assert!(encoder.copy(&source, &destination).is_err());
            encoder.upload(&source, &values)?;
            encoder.copy(&source.slice(1..3)?, &destination)?;
            let bindings = encoder.bind(
                &kernel,
                &[FieldBinding::ReadWrite(&destination)],
                "execution test",
            )?;
            assert!(encoder
                .dispatch(&kernel, &bindings, [0, 1, 1], "invalid test dispatch")
                .is_err());
            encoder.dispatch(&kernel, &bindings, [2, 1, 1], "execution test")?;
            encoder.submit()?.finish()?;
            let expected = values[1..3]
                .iter()
                .map(|value| *value + GoldilocksField::ONE)
                .collect::<Vec<_>>();
            assert_eq!(context.readback(&destination)?, expected);
            // Dropped encoders, including their encoded uploads, have no effect.
            let mut cancelled = workspace.begin(&context)?;
            cancelled.upload(&destination, &[GoldilocksField::ZERO; 2])?;
            drop(cancelled);
            assert_eq!(context.readback(&destination)?, expected);
        }
        {
            let _pending = other.begin(&context)?.submit()?;
        }
        other.wait(&context)?;
        drop(other.begin(&context)?);
        if context.info.backend == wgpu::Backend::Metal {
            let before = context.readback(&destination)?;
            // A small shared cap exercises rejection without approaching the
            // actual native queue limit. Cancel both encoders without submit.
            let pool = Arc::new(MetalCommandBufferPool::new(16));
            context.command_buffers = Some(pool.clone());
            let mut first = workspace.begin(&context)?;
            let first_bindings = first.bind(
                &kernel,
                &[FieldBinding::ReadWrite(&destination)],
                "shared capacity test",
            )?;
            for _ in 0..3 {
                first.dispatch(&kernel, &first_bindings, [2, 1, 1], "shared capacity test")?;
            }
            let mut second = other.begin(&context)?;
            let bindings = second.bind(
                &kernel,
                &[FieldBinding::ReadWrite(&foreign)],
                "shared capacity test",
            )?;
            second.dispatch(&kernel, &bindings, [2, 1, 1], "shared capacity test")?;
            let shared_error = "Metal command-buffer capacity is in use; finish outstanding work or drop unsubmitted encoders";
            assert_eq!(
                first
                    .dispatch(&kernel, &first_bindings, [2, 1, 1], "shared capacity test")
                    .unwrap_err()
                    .to_string(),
                shared_error
            );
            assert_eq!(
                context.readback(&destination).unwrap_err().to_string(),
                shared_error
            );
            assert_eq!(pool.used.load(Ordering::Acquire), 16);
            drop(second);
            drop(first);
            assert_eq!(pool.used.load(Ordering::Acquire), 0);
            assert_eq!(context.readback(&destination)?, before);
            let mut encoder = workspace.begin(&context)?;
            encoder.copy(&source.slice(1..3)?, &destination)?;
            encoder.submit()?.finish()?;
            assert_eq!(pool.used.load(Ordering::Acquire), 0);
            // An idle queue can still have reservations awaiting a callback.
            // Readback must process that callback before reserving capacity.
            let mut completed = MetalCommandBufferBudget::new(Some(pool.clone()))?;
            completed.reserve(12)?;
            context
                .queue
                .on_submitted_work_done(move || drop(completed));
            assert_eq!(pool.used.load(Ordering::Acquire), 16);
            assert_eq!(context.readback(&destination)?.len(), destination.len());
            assert_eq!(pool.used.load(Ordering::Acquire), 0);
            // Dropping the public token must not release a submitted reservation.
            {
                let _pending = other.begin(&context)?.submit()?;
            }
            other.wait(&context)?;
            assert_eq!(pool.used.load(Ordering::Acquire), 0);
        }
        context.device.destroy();
        assert!(workspace.begin(&context).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn hardware_fixed_data_is_shared_and_bindings_are_checked() -> Result<()> {
        let context = futures::executor::block_on(DeviceContext::new())?;
        let values = [
            GoldilocksField::from_canonical_u64(7),
            GoldilocksField::from_canonical_u64(11),
        ];
        let fixed = context.prepare_fixed(&values)?;
        assert_eq!(fixed.len(), 2);
        assert!(!fixed.is_empty());
        assert!(fixed.slice(1..3).is_err());
        assert_eq!(context.readback(&fixed.slice(1..2)?)?, values[1..2]);
        assert!(context.prepare_fixed(&[]).is_err());
        assert!(!fixed.buffer.usage().contains(wgpu::BufferUsages::COPY_DST));
        let source = "@group(0) @binding(0) var<storage, read> fixed: array<u64>;\n@group(0) @binding(1) var<storage, read_write> output: array<u64>;\n@compute @workgroup_size(1) fn main(@builtin(global_invocation_id) id: vec3<u32>) { output[id.x] = fixed[id.x] + 1lu; }";
        let specs = [
            FieldBindingSpec {
                access: BindingAccess::Read,
                min_elements: 2,
            },
            FieldBindingSpec {
                access: BindingAccess::ReadWrite,
                min_elements: 2,
            },
        ];
        let kernel = PreparedKernel::prepare(&context, source, &specs, "shared data test")?;
        let other_kernel = PreparedKernel::prepare(&context, source, &specs, "other kernel")?;
        let parameter_source = format!(
            "{}\n@group(0) @binding(2) var<uniform> params: vec4<u32>;",
            source.replace("fixed[id.x] + 1lu", "fixed[id.x] + u64(params.x)")
        );
        let parameter_kernel = PreparedKernel::prepare_entry(
            &context,
            &parameter_source,
            &specs,
            "parameter binding test",
            "main",
            true,
        )?;
        let params = context.prepare_params([1, 0, 0, 0])?;
        let writable_kernel = PreparedKernel::prepare(&context,
            "@group(0) @binding(0) var<storage, read_write> first: array<u64>;\n@group(0) @binding(1) var<storage, read_write> second: array<u64>;\n@compute @workgroup_size(1) fn main(@builtin(global_invocation_id) id: vec3<u32>) { first[id.x] = second[id.x]; }",
            &[FieldBindingSpec { access: BindingAccess::ReadWrite, min_elements: 2 }; 2], "writable alias test")?;
        let aligned_index = context.limits().min_storage_buffer_offset_alignment as usize / 8;
        let mut first = ProofWorkspace::prepare(&context, &[aligned_index + 2])?;
        let mut second = ProofWorkspace::prepare(&context, &[2])?;
        let first_allocation = first.buffer(0)?;
        let first_output = first_allocation.slice(0..2)?;
        let second_output = second.buffer(0)?;
        let other_device = futures::executor::block_on(DeviceContext::new())?;
        let foreign_fixed = other_device.prepare_fixed(&values)?;
        let foreign_params = other_device.prepare_params([1, 0, 0, 0])?;
        let saved_bindings;
        {
            let mut encoder = first.begin(&context)?;
            let fields = [
                FieldBinding::Read((&fixed).into()),
                FieldBinding::ReadWrite(&first_output),
            ];
            assert!(encoder
                .bind(&parameter_kernel, &fields, "missing parameters")
                .is_err());
            assert!(encoder
                .bind_with_params(
                    &parameter_kernel,
                    &fields,
                    Some(&foreign_params),
                    "foreign parameters"
                )
                .is_err());
            assert!(encoder
                .bind_with_params(&kernel, &fields, Some(&params), "unexpected parameters")
                .is_err());
            encoder.bind_with_params(
                &parameter_kernel,
                &fields,
                Some(&params),
                "valid parameters",
            )?;
            context.check_device()?;
            assert!(encoder.copy(&foreign_fixed, &first_output).is_err());
            assert!(encoder.bind(&kernel, &[], "missing bindings").is_err());
            assert!(encoder
                .bind(
                    &kernel,
                    &[
                        FieldBinding::Read((&fixed).into()),
                        FieldBinding::Read((&fixed).into())
                    ],
                    "fixed write rejected"
                )
                .is_err());
            assert!(encoder
                .bind(
                    &kernel,
                    &[
                        FieldBinding::Read((&foreign_fixed).into()),
                        FieldBinding::ReadWrite(&first_output)
                    ],
                    "foreign device"
                )
                .is_err());
            assert!(encoder
                .bind(
                    &kernel,
                    &[
                        FieldBinding::Read((&fixed).into()),
                        FieldBinding::ReadWrite(&second_output)
                    ],
                    "foreign workspace"
                )
                .is_err());
            let disjoint_read = first_allocation.slice(aligned_index..aligned_index + 2)?;
            let alias_error = encoder
                .bind(
                    &kernel,
                    &[
                        FieldBinding::Read((&disjoint_read).into()),
                        FieldBinding::ReadWrite(&first_output),
                    ],
                    "mixed storage alias",
                )
                .err()
                .context("mixed storage alias was accepted")?;
            assert!(alias_error
                .to_string()
                .contains("both read-only and writable"));
            context.check_device()?;
            assert!(encoder
                .bind(
                    &kernel,
                    &[
                        FieldBinding::Read((&fixed.slice(1..2)?).into()),
                        FieldBinding::ReadWrite(&first_output)
                    ],
                    "invalid view"
                )
                .is_err());
            encoder.copy(&fixed, &first_output)?;
            saved_bindings = encoder.bind(
                &kernel,
                &[
                    FieldBinding::Read((&fixed).into()),
                    FieldBinding::ReadWrite(&first_output),
                ],
                "first workspace",
            )?;
            assert!(encoder
                .dispatch(&other_kernel, &saved_bindings, [2, 1, 1], "wrong kernel")
                .is_err());
            encoder.dispatch(&kernel, &saved_bindings, [2, 1, 1], "first workspace")?;
            encoder.submit()?.finish()?;
        }
        {
            let mut encoder = second.begin(&context)?;
            assert!(encoder
                .dispatch(&kernel, &saved_bindings, [2, 1, 1], "wrong workspace")
                .is_err());
            assert!(encoder
                .bind(
                    &kernel,
                    &[
                        FieldBinding::Read((&first_output).into()),
                        FieldBinding::ReadWrite(&second_output)
                    ],
                    "foreign read"
                )
                .is_err());
            let bindings = encoder.bind(
                &kernel,
                &[
                    FieldBinding::Read((&fixed).into()),
                    FieldBinding::ReadWrite(&second_output),
                ],
                "second workspace",
            )?;
            encoder.dispatch(&kernel, &bindings, [2, 1, 1], "second workspace")?;
            encoder.submit()?.finish()?;
        }
        {
            // Two ReadWrite slots are not the mixed-usage conflict above.
            let mut encoder = first.begin(&context)?;
            let bindings = encoder.bind(
                &writable_kernel,
                &[
                    FieldBinding::ReadWrite(&first_output),
                    FieldBinding::ReadWrite(&first_output),
                ],
                "writable alias test",
            )?;
            encoder.dispatch(
                &writable_kernel,
                &bindings,
                [2, 1, 1],
                "writable alias test",
            )?;
            encoder.submit()?.finish()?;
        }
        let expected = values.map(|value| value + GoldilocksField::ONE);
        assert_eq!(context.readback(&first_output)?, expected);
        assert_eq!(context.readback(&second_output)?, expected);
        assert_eq!(context.readback(&fixed)?, values);
        Ok(())
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn hardware_read_only_layout_rejects_a_writing_shader() -> Result<()> {
        let context = futures::executor::block_on(DeviceContext::new())?;
        let result = PreparedKernel::prepare(&context,
            "@group(0) @binding(0) var<storage, read_write> fixed: array<u64>;\n@compute @workgroup_size(1) fn main() { fixed[0] = 0lu; }",
            &[FieldBindingSpec { access: BindingAccess::Read, min_elements: 1 }], "intentional fixed-write failure");
        let error = result
            .err()
            .context("writing shader was accepted")?
            .to_string();
        assert!(error.contains("Validation"), "{error}");
        Ok(())
    }

    #[test]
    #[ignore = "requires a hardware GPU with native u64 shader support"]
    fn hardware_validation_error_invalidates_context_without_panicking() -> Result<()> {
        let context = futures::executor::block_on(DeviceContext::new())?;
        let mut workspace = ProofWorkspace::prepare(&context, &[2])?;
        // Invalid MAP_READ usage provokes a real uncaptured wgpu validation
        // error without exhausting the machine's memory or touching its data.
        let _invalid = context.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("intentional validation failure"),
            size: 8,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::STORAGE,
            mapped_at_creation: false,
        });
        context.device.poll(wgpu::PollType::Poll)?;
        let error = context.check_device().unwrap_err().to_string();
        assert!(error.contains("Validation"), "{error}");
        assert!(ProofWorkspace::prepare(&context, &[2]).is_err());
        assert!(workspace.wait(&context).is_err());
        assert!(workspace.begin(&context).is_err());
        assert!(matches!(workspace.completion, Completion::Poisoned));
        Ok(())
    }
}
