use super::oracle::{workspace_views, OracleBuffers, OraclePlan};
use super::*;
use crate::operations::{read, write, FIELD};
use crate::runtime::KernelParams;
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::plonk::config::{GenericConfig, Hasher};

struct GatherBatch {
    columns: usize,
    params: Vec<KernelParams>,
}

pub(super) struct PreparedQuotient {
    pub evaluation: crate::QuotientPlan,
    pub fields: Vec<usize>,
    oracle: OraclePlan,
    inverse: FftPlan,
    gather: PreparedKernel,
    next: PreparedKernel,
    helpers_gather: PreparedKernel,
    helpers: FixedFieldSlice,
    fixed_batches: Vec<GatherBatch>,
    wire_batches: Vec<GatherBatch>,
    product_batches: Vec<GatherBatch>,
    next_batches: Vec<GatherBatch>,
    helper_batch: GatherBatch,
    tail: PreparedKernel,
    tail_params: KernelParams,
    chunk_rows: usize,
    challenges: usize,
    factor: usize,
}

fn chunk_capacity(rows: usize, columns: usize, limit: u64, maximum: usize) -> Result<usize> {
    // Swap axes: each chunk row consumes `columns` fields rather than vice versa.
    let capacity = column_capacity(columns, rows, limit, maximum)?;
    Ok(1usize << capacity.ilog2())
}

impl PreparedQuotient {
    pub fn prepare(
        context: &DeviceContext,
        circuit: &CircuitData<F, C, 2>,
        layout: &CircuitLayout,
        options: PreparationOptions,
        poseidon: Arc<PoseidonKernels>,
        fft: Arc<FftKernels>,
    ) -> Result<Self> {
        let common = &circuit.common;
        let c = common.config.num_challenges;
        let limit = context
            .limits()
            .max_buffer_size
            .min(u64::from(context.limits().max_storage_buffer_binding_size));
        let columns = crate::QuotientLayout::new(common).columns;
        let chunk_rows = chunk_capacity(
            layout.quotient_rows,
            columns,
            limit,
            options.quotient_chunk_rows,
        )?;
        ensure!(
            layout.quotient_rows as u64 * c as u64 * 8 <= limit
                && layout.quotient_rows as u64 * 3 * 8 <= limit,
            "quotient tables exceed storage-binding limit"
        );
        let evaluation = crate::QuotientPlan::prepare(context, common, chunk_rows)?;
        let l = evaluation.layout();
        let gather_source = |source_rows: usize, step: usize, rotation: usize| {
            include_str!("../shaders/quotient_gather.wgsl")
                .replace("__SOURCE_ROWS__", &source_rows.to_string())
                .replace("__QUOTIENT_ROWS__", &layout.quotient_rows.to_string())
                .replace("__STEP__", &step.to_string())
                .replace("__ROTATION__", &rotation.to_string())
        };
        let specs = [write(chunk_rows * columns), read(1)];
        let gather = PreparedKernel::prepare_entry(
            context,
            &gather_source(layout.lde_rows, layout.quotient_step, 0usize),
            &specs,
            "quotient oracle row gathering",
            "main",
            true,
        )?;
        let next = PreparedKernel::prepare_entry(
            context,
            &gather_source(
                layout.lde_rows,
                layout.quotient_step,
                layout.quotient_rows / layout.degree,
            ),
            &specs,
            "quotient next-row gathering",
            "main",
            true,
        )?;
        let helpers_gather = PreparedKernel::prepare_entry(
            context,
            &gather_source(layout.quotient_rows, 1usize, 0usize),
            &specs,
            "quotient fixed helper gathering",
            "main",
            true,
        )?;
        let batches_for = |counts: &[usize], first: usize| -> Result<Vec<GatherBatch>> {
            let mut column = first;
            counts
                .iter()
                .map(|&count| {
                    let batch = GatherBatch {
                        columns: count,
                        params: (0..layout.quotient_rows)
                            .step_by(chunk_rows)
                            .map(|offset| {
                                context.prepare_params([
                                    chunk_rows as u32,
                                    offset as u32,
                                    column as u32,
                                    count as u32,
                                ])
                            })
                            .collect::<Result<_>>()?,
                    };
                    column += count;
                    Ok(batch)
                })
                .collect()
        };
        let fixed_batches = batches_for(
            &batches(
                common.num_constants + common.config.num_routed_wires,
                layout.columns_per_batch,
            ),
            l.constants,
        )?;
        let wire_batches = batches_for(&layout.batch_columns, l.wires)?;
        let product_width = c * (common.num_partial_products + 1);
        let product_columns = batches(
            product_width,
            column_capacity(
                layout.lde_rows,
                product_width,
                limit,
                options.max_columns_per_batch,
            )?,
        );
        let product_batches = batches_for(&product_columns, l.zs)?;
        let mut remaining = c;
        let next_columns = product_columns
            .iter()
            .filter_map(|&count| {
                let count = count.min(remaining);
                remaining -= count;
                (count > 0).then_some(count)
            })
            .collect::<Vec<_>>();
        let next_batches = batches_for(&next_columns, l.next_zs)?;
        let helper_batch = batches_for(&[3], l.x)?.pop().unwrap();
        let root = F::primitive_root_of_unity(layout.quotient_rows.ilog2() as usize);
        let xs = root
            .powers()
            .take(layout.quotient_rows)
            .map(|point| point * F::coset_shift())
            .collect::<Vec<_>>();
        let zero = ZeroPolyOnCoset::<F>::try_new(
            layout.degree.ilog2() as usize,
            (layout.quotient_rows / layout.degree).ilog2() as usize,
        )?;
        let denominators = xs
            .iter()
            .map(|&x| F::from_canonical_usize(layout.degree) * (x - F::ONE))
            .collect::<Vec<_>>();
        let inverses = F::batch_multiplicative_inverse(&denominators);
        let mut helpers = xs;
        helpers.extend(
            inverses
                .into_iter()
                .enumerate()
                .map(|(i, inv)| zero.eval(i) * inv),
        );
        helpers.extend((0..layout.quotient_rows).map(|i| zero.eval_inverse(i)));
        let helpers = context.prepare_fixed(&helpers)?;
        let inverse =
            FftPlan::prepare_inverse(context, fft, layout.quotient_rows, F::coset_shift())?;
        let oracle = OraclePlan::prepare(
            context,
            circuit,
            layout,
            options,
            poseidon,
            c * common.quotient_degree_factor,
            false,
        )?;
        let tail = PreparedKernel::prepare_entry(
            context,
            &format!("{FIELD}\n{}", include_str!("../shaders/quotient_tail.wgsl")),
            &[write(1), read(c * layout.quotient_rows)],
            "quotient degree validation",
            "main",
            true,
        )?;
        let tail_params = context.prepare_params([
            layout.quotient_rows as u32,
            common.quotient_degree() as u32,
            c as u32,
            0,
        ])?;
        let mut fields = evaluation.workspace_field_counts().to_vec();
        fields.extend([c * layout.quotient_rows, c * layout.quotient_rows, 1]);
        fields.extend_from_slice(&oracle.fields);
        Ok(Self {
            evaluation,
            fields,
            oracle,
            inverse,
            gather,
            next,
            helpers_gather,
            helpers,
            fixed_batches,
            wire_batches,
            product_batches,
            next_batches,
            helper_batch,
            tail,
            tail_params,
            chunk_rows,
            challenges: c,
            factor: common.quotient_degree_factor,
        })
    }
}

/// Per-proof quotient row scratch, interpolation buffers, and output oracle.
pub struct QuotientBuffers<'c, 'a> {
    prepared: &'c PreparedCircuit<'a>,
    rows: DeviceFieldSlice,
    scalars: DeviceFieldSlice,
    weights: DeviceFieldSlice,
    chunk_values: DeviceFieldSlice,
    values: DeviceFieldSlice,
    coefficients: DeviceFieldSlice,
    status: DeviceFieldSlice,
    oracle: OracleBuffers,
}

/// Committed degree-n quotient chunks, challenge first then chunk, as in the
/// CPU prover. Full quotient values/coefficients stay resident for inspection.
pub struct QuotientCommitment {
    pub oracle: PolynomialCommitment,
    pub full_evaluations: DeviceFieldSlice,
    pub full_coefficients: DeviceFieldSlice,
    status: DeviceFieldSlice,
}

impl QuotientCommitment {
    /// Enforce the CPU's trim_to_len check before returning a proof. This is an
    /// explicit one-field export, never performed by encode().
    pub fn check_status(&self, context: &DeviceContext) -> Result<()> {
        ensure!(
            context.readback(&self.status)? == [F::ZERO],
            "quotient has nonzero coefficients beyond its permitted degree"
        );
        Ok(())
    }
}

impl<'a> PreparedCircuit<'a> {
    pub fn quotient_workspace_field_counts(&self) -> &[usize] {
        &self.quotient.fields
    }

    pub fn quotient_buffers(
        &self,
        workspace: &ProofWorkspace,
        first: usize,
    ) -> Result<QuotientBuffers<'_, 'a>> {
        let buffers = workspace_views(workspace, first, &self.quotient.fields)?;
        Ok(QuotientBuffers {
            prepared: self,
            rows: buffers[0].clone(),
            scalars: buffers[1].clone(),
            weights: buffers[2].clone(),
            chunk_values: buffers[3].clone(),
            values: buffers[4].clone(),
            coefficients: buffers[5].clone(),
            status: buffers[6].clone(),
            oracle: self.quotient.oracle.buffers(workspace, first + 7)?,
        })
    }
}

impl QuotientBuffers<'_, '_> {
    fn gather(
        &self,
        encoder: &mut ProofEncoder<'_>,
        kernel: &PreparedKernel,
        batches: &[GatherBatch],
        sources: &[FieldSource<'_>],
        chunk: usize,
    ) -> Result<()> {
        for (batch, &source) in batches.iter().zip(sources) {
            let group = encoder.bind_with_params(
                kernel,
                &[
                    FieldBinding::ReadWrite(&self.rows),
                    FieldBinding::Read(source),
                ],
                Some(&batch.params[chunk]),
                "quotient row gathering",
            )?;
            encoder.dispatch_elements(
                kernel,
                &group,
                self.prepared.quotient.chunk_rows * batch.columns,
                "quotient row gathering",
            )?;
        }
        Ok(())
    }

    /// Use betas/gammas from the permutation stage and alphas supplied after
    /// the coordinator observes its cap. Hash the CPU public-input vector once;
    /// all oracle gathering, evaluation, interpolation and splitting run on GPU.
    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        wires: &WireCommitment,
        permutation: &PermutationCommitment,
        alphas: &[F],
    ) -> Result<QuotientCommitment> {
        let prepared = self.prepared;
        let plan = &prepared.quotient;
        ensure!(
            alphas.len() == plan.challenges
                && permutation.betas.len() == plan.challenges
                && permutation.gammas.len() == plan.challenges,
            "quotient challenge count mismatch"
        );
        let check_batches = |buffers: &[DeviceFieldSlice], batches: &[GatherBatch]| {
            buffers.len() == batches.len()
                && buffers
                    .iter()
                    .zip(batches)
                    .all(|(buffer, batch)| buffer.len() == batch.columns * prepared.layout.lde_rows)
        };
        ensure!(
            check_batches(&wires.evaluations, &plan.wire_batches)
                && check_batches(&permutation.oracle.evaluations, &plan.product_batches),
            "quotient oracle buffer shape mismatch"
        );
        let hash = <C as GenericConfig<2>>::InnerHasher::hash_no_pad(&wires.public_inputs);
        encoder.upload(
            &self.scalars,
            &[
                hash.elements.as_slice(),
                permutation.betas.as_slice(),
                permutation.gammas.as_slice(),
                alphas,
            ]
            .concat(),
        )?;
        encoder.upload(&self.status, &[F::ZERO])?;
        plan.evaluation
            .encode_weights(encoder, &self.scalars, &self.weights)?;
        let fixed = prepared
            .fixed
            .evaluations
            .iter()
            .map(FieldSource::from)
            .collect::<Vec<_>>();
        let wire_sources = wires
            .evaluations
            .iter()
            .map(FieldSource::from)
            .collect::<Vec<_>>();
        let product_sources = permutation
            .oracle
            .evaluations
            .iter()
            .map(FieldSource::from)
            .collect::<Vec<_>>();
        for (chunk, offset) in (0..prepared.layout.quotient_rows)
            .step_by(plan.chunk_rows)
            .enumerate()
        {
            self.gather(encoder, &plan.gather, &plan.fixed_batches, &fixed, chunk)?;
            self.gather(
                encoder,
                &plan.gather,
                &plan.wire_batches,
                &wire_sources,
                chunk,
            )?;
            self.gather(
                encoder,
                &plan.gather,
                &plan.product_batches,
                &product_sources,
                chunk,
            )?;
            self.gather(
                encoder,
                &plan.next,
                &plan.next_batches,
                &product_sources,
                chunk,
            )?;
            self.gather(
                encoder,
                &plan.helpers_gather,
                std::slice::from_ref(&plan.helper_batch),
                &[(&plan.helpers).into()],
                chunk,
            )?;
            plan.evaluation.encode_rows(
                encoder,
                &self.rows,
                &self.scalars,
                &self.weights,
                &self.chunk_values,
            )?;
            for challenge in 0..plan.challenges {
                encoder.copy(
                    &self
                        .chunk_values
                        .slice(challenge * plan.chunk_rows..(challenge + 1) * plan.chunk_rows)?,
                    &self.values.slice(
                        challenge * prepared.layout.quotient_rows + offset
                            ..challenge * prepared.layout.quotient_rows + offset + plan.chunk_rows,
                    )?,
                )?;
            }
        }
        plan.inverse
            .encode(encoder, &self.values, &self.coefficients)?;
        let group = encoder.bind_with_params(
            &plan.tail,
            &[
                FieldBinding::ReadWrite(&self.status),
                FieldBinding::Read((&self.coefficients).into()),
            ],
            Some(&plan.tail_params),
            "quotient degree validation",
        )?;
        encoder.dispatch_elements(
            &plan.tail,
            &group,
            self.coefficients.len(),
            "quotient degree validation",
        )?;
        let mut column = 0;
        for (coefficients, &columns) in self.oracle.coefficients.iter().zip(&plan.oracle.columns) {
            for local in 0..columns {
                let start = (column / plan.factor) * prepared.layout.quotient_rows
                    + (column % plan.factor) * prepared.layout.degree;
                encoder.copy(
                    &self
                        .coefficients
                        .slice(start..start + prepared.layout.degree)?,
                    &coefficients.slice(
                        local * prepared.layout.degree..(local + 1) * prepared.layout.degree,
                    )?,
                )?;
                column += 1;
            }
        }
        Ok(QuotientCommitment {
            oracle: plan
                .oracle
                .encode_coefficients(prepared, encoder, &self.oracle)?,
            full_evaluations: self.values.clone(),
            full_coefficients: self.coefficients.clone(),
            status: self.status.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
