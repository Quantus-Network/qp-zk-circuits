//! Circuit-invariant preparation and the first resident proving stage.
use crate::runtime::{BindingAccess, FieldBinding, FieldBindingSpec, PreparedKernel};
use crate::{
    CommitmentPlan, DeviceContext, DeviceFieldSlice, EvaluationOrder, FftKernels, FftPlan,
    FieldSource, FixedFieldSlice, PoseidonKernels, ProofEncoder, ProofWorkspace,
};
use anyhow::{ensure, Context, Result};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::witness::{PartialWitness, PartitionWitness, Witness};
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::PoseidonGoldilocksConfig as C;
use plonky2::util::log2_ceil;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Resource limits, not protocol parameters. Column batches are further bounded
/// by the adapter's storage-binding limit. Chunk sizes bound reusable scratch.
#[derive(Clone, Copy, Debug)]
pub struct PreparationOptions {
    pub max_columns_per_batch: usize,
    pub commitment_chunk_rows: usize,
    pub quotient_chunk_rows: usize,
}

impl Default for PreparationOptions {
    fn default() -> Self {
        Self {
            max_columns_per_batch: usize::MAX,
            commitment_chunk_rows: 1 << 16,
            quotient_chunk_rows: 1 << 16,
        }
    }
}

/// Host wall time for initialization, including native pipeline creation.
/// These are not GPU execution timestamps or per-proof measurements.
#[derive(Clone, Copy, Debug, Default)]
pub struct CircuitPreparationTimings {
    pub kernels: Duration,
    pub fft_tables: Duration,
    pub fixed_data: Duration,
    pub quotient: Duration,
}

/// Immutable constants/sigmas oracle, shared across proof workspaces. Batches
/// contain contiguous polynomial columns, with natural-order evaluations.
/// The tree uses the CPU's packed digest layout followed by its cap.
pub struct FixedCommitment {
    pub coefficients: Vec<FixedFieldSlice>,
    pub evaluations: Vec<FixedFieldSlice>,
    pub tree: FixedFieldSlice,
    pub cap: FixedFieldSlice,
}

/// Host-only validation and layout derivation, run before GPU preparation.
struct CircuitLayout {
    degree: usize,
    lde_rows: usize,
    quotient_rows: usize,
    quotient_step: usize,
    columns_per_batch: usize,
    batch_columns: Vec<usize>,
}

impl CircuitLayout {
    fn new(
        circuit: &CircuitData<F, C, 2>,
        options: PreparationOptions,
        limit: u64,
    ) -> Result<Self> {
        let common = &circuit.common;
        ensure!(
            common.quotient_degree_factor > 0,
            "quotient degree factor is zero"
        );
        common.check_valid().map_err(anyhow::Error::msg)?;
        ensure!(
            !common.config.zero_knowledge,
            "GPU wire blinding is not implemented"
        );
        ensure!(
            common.num_lookup_polys == 0 && common.luts.is_empty(),
            "GPU lookup witnesses are not implemented"
        );
        ensure!(
            common.public_initial_degree_bits() == common.degree_bits(),
            "GPU degree lifting is not implemented"
        );
        ensure!(
            options.max_columns_per_batch > 0
                && options.commitment_chunk_rows > 0
                && options.quotient_chunk_rows > 0,
            "preparation resource limits must be nonzero"
        );
        let degree = common.degree();
        let (lde_rows, quotient_rows, quotient_step) = evaluation_domains(
            degree,
            common.config.fri_config.rate_bits,
            common.quotient_degree_factor,
        )?;
        let width = common.config.num_wires;
        let representatives = &circuit.prover_only.representative_map;
        ensure!(
            representatives.len() >= degree.checked_mul(width).context("wire table overflow")?,
            "incomplete circuit representative map"
        );
        ensure!(
            representatives.len() <= u32::MAX as usize
                && representatives
                    .iter()
                    .all(|&rep| rep < representatives.len()),
            "invalid circuit representative indices"
        );
        ensure!(
            representatives.len() as u64 * 8 <= limit,
            "partition witness exceeds storage-binding limit"
        );
        let oracle = &circuit.prover_only.constants_sigmas_commitment;
        ensure!(
            oracle.polynomials.len() == common.num_constants + common.config.num_routed_wires
                && oracle.merkle_tree.cap == circuit.verifier_only.constants_sigmas_cap,
            "fixed oracle does not match circuit metadata"
        );
        validate_fixed_commitment(oracle, degree, lde_rows)?;
        let columns_per_batch =
            column_capacity(lde_rows, width, limit, options.max_columns_per_batch)?;
        Ok(Self {
            degree,
            lde_rows,
            quotient_rows,
            quotient_step,
            columns_per_batch,
            batch_columns: batches(width, columns_per_batch),
        })
    }
}

fn evaluation_domains(
    degree: usize,
    rate_bits: usize,
    quotient_factor: usize,
) -> Result<(usize, usize, usize)> {
    ensure!(
        degree.is_power_of_two() && quotient_factor > 0,
        "invalid evaluation domain"
    );
    let quotient_bits = log2_ceil(quotient_factor);
    ensure!(
        quotient_bits <= rate_bits,
        "quotient domain exceeds LDE domain"
    );
    let expanded = |bits: usize| -> Result<usize> {
        let factor = 1usize
            .checked_shl(u32::try_from(bits)?)
            .context("evaluation domain overflow")?;
        degree
            .checked_mul(factor)
            .context("evaluation domain overflow")
    };
    let lde_rows = expanded(rate_bits)?;
    let quotient_rows = expanded(quotient_bits)?;
    Ok((lde_rows, quotient_rows, lde_rows / quotient_rows))
}

/// Prepared for this exact borrowed CPU circuit, not just its dimensions.
/// The borrow prevents replacing circuit data while its fixed GPU resources
/// are in use. Wire-buffer views borrow this object and cannot switch circuits.
///
/// Currently supports non-ZK Goldilocks/Poseidon circuits without lookups or
/// degree lifting. These configurations fail before shader compilation.
pub struct PreparedCircuit<'a> {
    circuit: &'a CircuitData<F, C, 2>,
    layout: CircuitLayout,
    wire_maps: Vec<FixedFieldSlice>,
    gather: PreparedKernel,
    inverse: FftPlan,
    forward: FftPlan,
    commitment: CommitmentPlan,
    fixed: FixedCommitment,
    wire_workspace_fields: Vec<usize>,
    timings: CircuitPreparationTimings,
    #[cfg(feature = "constraint-export")]
    quotient: crate::QuotientPlan,
}

impl<'a> PreparedCircuit<'a> {
    pub fn prepare(
        context: &DeviceContext,
        circuit: &'a CircuitData<F, C, 2>,
        options: PreparationOptions,
    ) -> Result<Self> {
        let limit = context
            .limits()
            .max_buffer_size
            .min(u64::from(context.limits().max_storage_buffer_binding_size));
        let layout = CircuitLayout::new(circuit, options, limit)?;
        let common = &circuit.common;
        let degree = layout.degree;
        let rows = layout.lde_rows;
        let width = common.config.num_wires;
        let representatives = &circuit.prover_only.representative_map;
        let started = Instant::now();
        let commitment = Arc::new(PoseidonKernels::prepare(context)?);
        let fft = Arc::new(FftKernels::prepare(context)?);
        let gather = PreparedKernel::prepare(
            context,
            include_str!("shaders/witness.wgsl"),
            &[
                FieldBindingSpec {
                    access: BindingAccess::ReadWrite,
                    min_elements: 1,
                },
                FieldBindingSpec {
                    access: BindingAccess::Read,
                    min_elements: 1,
                },
                FieldBindingSpec {
                    access: BindingAccess::Read,
                    min_elements: representatives.len(),
                },
            ],
            "witness wire gathering",
        )?;
        let mut timings = CircuitPreparationTimings {
            kernels: started.elapsed(),
            ..Default::default()
        };
        let started = Instant::now();
        let inverse = FftPlan::prepare_inverse(context, Arc::clone(&fft), degree, F::ONE)?;
        let forward = FftPlan::prepare_coset(context, fft, degree, rows, F::coset_shift())?;
        let commitment = CommitmentPlan::prepare_chunked(
            context,
            commitment,
            rows,
            width,
            common.config.fri_config.cap_height,
            EvaluationOrder::BitReversed,
            options.commitment_chunk_rows,
        )?;
        timings.fft_tables = started.elapsed();
        let started = Instant::now();
        let mut first_column = 0;
        let wire_maps = layout
            .batch_columns
            .iter()
            .map(|&columns| {
                let map = (first_column..first_column + columns)
                    .flat_map(|column| {
                        (0..degree).map(move |row| {
                            F::from_canonical_usize(representatives[row * width + column])
                        })
                    })
                    .collect::<Vec<_>>();
                first_column += columns;
                context.prepare_fixed(&map)
            })
            .collect::<Result<_>>()?;
        let fixed = prepare_fixed_commitment(
            context,
            &circuit.prover_only.constants_sigmas_commitment,
            rows,
            layout.columns_per_batch,
        )?;
        timings.fixed_data = started.elapsed();
        #[cfg(feature = "constraint-export")]
        let quotient = {
            let started = Instant::now();
            let plan = crate::QuotientPlan::prepare(
                context,
                common,
                options.quotient_chunk_rows.min(layout.quotient_rows),
            )?;
            timings.quotient = started.elapsed();
            plan
        };
        let mut wire_workspace_fields = vec![representatives.len()];
        for &columns in &layout.batch_columns {
            wire_workspace_fields.extend([degree * columns, degree * columns, rows * columns]);
        }
        wire_workspace_fields.extend(commitment.workspace_field_counts());
        Ok(Self {
            circuit,
            layout,
            wire_maps,
            gather,
            inverse,
            forward,
            commitment,
            fixed,
            wire_workspace_fields,
            timings,
            #[cfg(feature = "constraint-export")]
            quotient,
        })
    }

    pub fn timings(&self) -> CircuitPreparationTimings {
        self.timings
    }
    pub fn degree(&self) -> usize {
        self.layout.degree
    }

    /// FRI/LDE coset rows. Merkle commitments use this domain; quotient
    /// evaluation may use a smaller domain, even for the same circuit.
    pub fn evaluation_rows(&self) -> usize {
        self.layout.lde_rows
    }

    pub fn quotient_rows(&self) -> usize {
        self.layout.quotient_rows
    }

    /// Quotient row i reads LDE row i * step. Its x, L0 and 1/Z_H helpers must
    /// use the quotient coset, not an unstrided copy of the LDE coset.
    pub fn quotient_evaluation_step(&self) -> usize {
        self.layout.quotient_step
    }

    /// One u64 per partition slot, including virtual targets. Representatives
    /// may live in virtual slots, so uploading only wire slots is insufficient.
    pub fn witness_upload_bytes(&self) -> u64 {
        self.wire_workspace_fields[0] as u64 * 8
    }
    pub fn fixed_commitment(&self) -> &FixedCommitment {
        &self.fixed
    }

    #[cfg(feature = "constraint-export")]
    pub fn quotient_plan(&self) -> &crate::QuotientPlan {
        &self.quotient
    }

    /// Append these counts to the shared per-proof allocation plan. Other
    /// stages append their own counts and use the same ProofWorkspace/encoder.
    pub fn wire_workspace_field_counts(&self) -> &[usize] {
        &self.wire_workspace_fields
    }

    /// View the wire-stage allocation range, starting at first_buffer in the
    /// shared workspace. This does not allocate, begin encoding, or submit work.
    pub fn wire_buffers(
        &self,
        workspace: &ProofWorkspace,
        first_buffer: usize,
    ) -> Result<WireBuffers<'_, 'a>> {
        let buffers = self
            .wire_workspace_fields
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                let buffer = workspace.buffer(
                    first_buffer
                        .checked_add(index)
                        .context("wire buffer index overflow")?,
                )?;
                ensure!(buffer.len() == len, "wire workspace buffer shape mismatch");
                Ok(buffer)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut wires = Vec::new();
        let mut coefficients = Vec::new();
        let mut evaluations = Vec::new();
        for batch in 0..self.layout.batch_columns.len() {
            wires.push(buffers[1 + 3 * batch].clone());
            coefficients.push(buffers[2 + 3 * batch].clone());
            evaluations.push(buffers[3 + 3 * batch].clone());
        }
        let scratch = 1 + 3 * self.layout.batch_columns.len();
        Ok(WireBuffers {
            prepared: self,
            representatives: buffers[0].clone(),
            wires,
            coefficients,
            evaluations,
            input_chunk: buffers[scratch].clone(),
            leaf_chunk: buffers[scratch + 1].clone(),
            tree: buffers[scratch + 2].clone(),
        })
    }
}

fn column_capacity(rows: usize, width: usize, limit: u64, maximum: usize) -> Result<usize> {
    ensure!(
        rows > 0 && width > 0 && maximum > 0,
        "empty polynomial batch"
    );
    let column_bytes = (rows as u64)
        .checked_mul(8)
        .context("polynomial size overflow")?;
    let capacity = (limit / column_bytes).min(width as u64).min(maximum as u64) as usize;
    ensure!(capacity > 0, "one polynomial exceeds storage-binding limit");
    Ok(capacity)
}

fn batches(width: usize, capacity: usize) -> Vec<usize> {
    (0..width)
        .step_by(capacity)
        .map(|start| capacity.min(width - start))
        .collect()
}

fn validate_fixed_commitment(
    oracle: &PolynomialBatch<F, C, 2>,
    degree: usize,
    rows: usize,
) -> Result<()> {
    ensure!(
        !oracle.blinding
            && oracle.degree_log == degree.ilog2() as usize
            && oracle.merkle_tree.leaves.len() == rows,
        "fixed oracle domain mismatch"
    );
    let width = oracle.polynomials.len();
    ensure!(
        width > 0
            && oracle.polynomials.iter().all(|p| p.coeffs.len() == degree)
            && oracle
                .merkle_tree
                .leaves
                .iter()
                .all(|row| row.len() == width),
        "fixed oracle polynomial shape mismatch"
    );
    Ok(())
}

fn prepare_fixed_commitment(
    context: &DeviceContext,
    oracle: &PolynomialBatch<F, C, 2>,
    rows: usize,
    capacity: usize,
) -> Result<FixedCommitment> {
    // CircuitData already owns this CPU-prepared oracle. Upload it once rather
    // than recomputing fixed FFTs and Merkle hashing for every proof.
    let width = oracle.polynomials.len();
    let mut coefficients = Vec::new();
    let mut evaluations = Vec::new();
    for first in (0..width).step_by(capacity) {
        let end = (first + capacity).min(width);
        let coeffs = oracle.polynomials[first..end]
            .iter()
            .flat_map(|p| p.coeffs.iter().copied())
            .collect::<Vec<_>>();
        coefficients.push(context.prepare_fixed(&coeffs)?);
        let values = (first..end)
            .flat_map(|column| (0..rows).map(move |row| oracle.get_lde_values(row, 1)[column]))
            .collect::<Vec<_>>();
        evaluations.push(context.prepare_fixed(&values)?);
    }
    let tree_values = oracle
        .merkle_tree
        .digests
        .iter()
        .chain(&oracle.merkle_tree.cap.0)
        .flat_map(|hash| hash.elements)
        .collect::<Vec<_>>();
    let tree = context.prepare_fixed(&tree_values)?;
    let cap = tree.slice(tree.len() - 4 * oracle.merkle_tree.cap.0.len()..tree.len())?;
    Ok(FixedCommitment {
        coefficients,
        evaluations,
        tree,
        cap,
    })
}

/// Circuit-bound views of the wire-stage buffers in a caller-owned, per-proof
/// workspace. Encoding uses its exclusive lease; other stages can consume the
/// resident outputs using the same encoder, without copying between workspaces.
/// These views pin allocations and are overwritten on workspace reuse.
pub struct WireBuffers<'c, 'a> {
    prepared: &'c PreparedCircuit<'a>,
    representatives: DeviceFieldSlice,
    wires: Vec<DeviceFieldSlice>,
    coefficients: Vec<DeviceFieldSlice>,
    evaluations: Vec<DeviceFieldSlice>,
    input_chunk: DeviceFieldSlice,
    leaf_chunk: DeviceFieldSlice,
    tree: DeviceFieldSlice,
}

/// Resident wire oracle and the CPU public inputs extracted from its witness.
/// Only explicit readback exports field data; commitment construction does not.
/// Later commands in the same encoder can consume these views. Host exports
/// must follow submission completion; dropping the encoder cancels its writes.
pub struct WireCommitment {
    pub public_inputs: Vec<F>,
    /// Subgroup wire columns, retained for permutation-product generation.
    pub wire_values: Vec<DeviceFieldSlice>,
    pub coefficients: Vec<DeviceFieldSlice>,
    pub evaluations: Vec<DeviceFieldSlice>,
    pub tree: DeviceFieldSlice,
    pub cap: DeviceFieldSlice,
}

impl WireBuffers<'_, '_> {
    /// Finish CPU witness generators, upload representative values once, then
    /// encode column gathering, IFFT, coset FFT, and Merkle commitment.
    /// Does not submit, wait for completion, or read a cap back. The caller can
    /// append other stages before submitting the shared encoder, and must
    /// finish the submission or call ProofWorkspace::wait before reusing it.
    /// Dropping a pending token alone does not wait for GPU completion.
    /// This accepts the output of PublicBatchProver::build_witness; it does not
    /// replace proof admission.
    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        inputs: PartialWitness<F>,
    ) -> Result<WireCommitment> {
        let prepared = self.prepared;
        let partition = generate_partial_witness(
            inputs,
            &prepared.circuit.prover_only,
            &prepared.circuit.common,
        )
        .context("generate public-batch witness")?;
        self.encode_generated(encoder, partition)
    }

    fn encode_generated(
        &self,
        encoder: &mut ProofEncoder<'_>,
        partition: PartitionWitness<'_, F>,
    ) -> Result<WireCommitment> {
        let prepared = self.prepared;
        let public_inputs = prepared
            .circuit
            .prover_only
            .public_inputs
            .iter()
            .map(|&target| {
                partition
                    .try_get_target(target)
                    .context("missing public-input witness value")
            })
            .collect::<Result<_>>()?;
        // CPU full_witness uses zero for unassigned partitions too. Do not
        // expand or transpose the wire matrix on the host.
        let values = partition
            .values
            .into_iter()
            .map(|value| value.unwrap_or(F::ZERO))
            .collect::<Vec<_>>();
        let cap = prepared.commitment.cap(&self.tree)?;
        encoder.upload(&self.representatives, &values)?;
        for batch in 0..self.wires.len() {
            let bindings = encoder.bind(
                &prepared.gather,
                &[
                    FieldBinding::ReadWrite(&self.wires[batch]),
                    FieldBinding::Read((&prepared.wire_maps[batch]).into()),
                    FieldBinding::Read((&self.representatives).into()),
                ],
                "witness wire gathering",
            )?;
            encoder.dispatch_elements(
                &prepared.gather,
                &bindings,
                self.wires[batch].len(),
                "witness wire gathering",
            )?;
            prepared
                .inverse
                .encode(encoder, &self.wires[batch], &self.coefficients[batch])?;
            prepared.forward.encode(
                encoder,
                &self.coefficients[batch],
                &self.evaluations[batch],
            )?;
        }
        let columns = self
            .evaluations
            .iter()
            .zip(&prepared.layout.batch_columns)
            .flat_map(|(batch, &columns)| {
                (0..columns).map(move |column| {
                    batch.slice(
                        column * prepared.layout.lde_rows..(column + 1) * prepared.layout.lde_rows,
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let sources = columns.iter().map(FieldSource::from).collect::<Vec<_>>();
        prepared.commitment.encode(
            encoder,
            &sources,
            &self.input_chunk,
            &self.leaf_chunk,
            &self.tree,
        )?;
        Ok(WireCommitment {
            public_inputs,
            wire_values: self.wires.clone(),
            coefficients: self.coefficients.clone(),
            evaluations: self.evaluations.clone(),
            tree: self.tree.clone(),
            cap,
        })
    }
}

#[cfg(test)]
mod tests;
