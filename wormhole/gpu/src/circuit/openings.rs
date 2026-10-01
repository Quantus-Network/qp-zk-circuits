use super::oracle::workspace_views;
use super::*;
use crate::operations::{read, write, EXTENSION, FIELD};
use crate::runtime::KernelParams;
use crate::{
    ExtensionKernels, LinearDivisionPlan, PolynomialCombinationPlan, PolynomialEvaluationPlan,
};
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::types::PrimeField64;
use plonky2::fri::structure::{FriCoefficient, FriInstanceInfo};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::OpeningSet;

type E = QuadraticExtension<F>;

#[derive(Clone, Copy)]
pub(super) struct OpeningLayout {
    widths: [usize; 4],
    constants: usize,
    next: usize,
}

impl OpeningLayout {
    pub fn new(common: &CommonCircuitData<F, 2>) -> Result<Self> {
        Self::from_instance(common, common.get_fri_instance(E::ONE))
    }

    fn from_instance(
        common: &CommonCircuitData<F, 2>,
        instance: FriInstanceInfo<F, 2>,
    ) -> Result<Self> {
        let widths = [
            common.num_constants + common.config.num_routed_wires,
            common.config.num_wires,
            common.config.num_challenges * (common.num_partial_products + 1),
            common.config.num_challenges * common.quotient_degree_factor,
        ];
        ensure!(
            instance.oracles.len() == 4
                && instance.batches.len() == 2
                && instance
                    .oracles
                    .iter()
                    .zip(widths)
                    .all(|(oracle, width)| oracle.num_polys == width),
            "unsupported FRI opening oracle structure"
        );
        ensure!(
            instance.batches[0].point == E::ONE
                && instance.batches[1].point == E::primitive_root_of_unity(common.degree_bits()),
            "unsupported FRI opening points"
        );
        let expected = [
            widths
                .iter()
                .enumerate()
                .flat_map(|(oracle, &width)| (0..width).map(move |column| (oracle, column)))
                .collect::<Vec<_>>(),
            (0..common.config.num_challenges)
                .map(|column| (2, column))
                .collect::<Vec<_>>(),
        ];
        for (batch, expected) in instance.batches.iter().zip(expected) {
            ensure!(
                batch.openings.len() == expected.len(),
                "unsupported FRI opening batch width"
            );
            for (expression, (oracle, column)) in batch.openings.iter().zip(expected) {
                ensure!(
                    expression.terms.len() == 1
                        && matches!(expression.terms[0].coefficient, FriCoefficient::One)
                        && expression.terms[0].polynomial.oracle_index == oracle
                        && expression.terms[0].polynomial.polynomial_index == column,
                    "unsupported FRI opening expression or order"
                );
            }
        }
        Ok(Self {
            widths,
            constants: common.num_constants,
            next: common.config.num_challenges,
        })
    }

    fn all(&self) -> usize {
        self.widths.iter().sum()
    }
    fn total(&self) -> usize {
        self.all() + self.next
    }
}

struct CoefficientBatch {
    source: usize,
    columns: usize,
    first_opening: usize,
    evaluation: PolynomialEvaluationPlan,
    combination: PolynomialCombinationPlan,
}

pub(super) struct PreparedOpenings {
    layout: OpeningLayout,
    fields: Vec<usize>,
    all: Vec<CoefficientBatch>,
    next: Vec<CoefficientBatch>,
    division: [LinearDivisionPlan; 2],
    points: PreparedKernel,
    weights: PreparedKernel,
    merge: PreparedKernel,
    params: KernelParams,
    merge_params: [KernelParams; 2],
    eval_scratch: usize,
}

impl PreparedOpenings {
    pub fn prepare(
        context: &DeviceContext,
        common: &CommonCircuitData<F, 2>,
        layout: &CircuitLayout,
        options: PreparationOptions,
        kernels: Arc<ExtensionKernels>,
    ) -> Result<Self> {
        let description = layout.openings;
        let limit = context
            .limits()
            .max_buffer_size
            .min(u64::from(context.limits().max_storage_buffer_binding_size));
        let mut all = Vec::new();
        let mut next = Vec::new();
        let mut first = 0;
        let mut remaining = description.next;
        for (oracle, &width) in description.widths.iter().enumerate() {
            let capacity = if oracle < 2 {
                layout.columns_per_batch
            } else {
                column_capacity(layout.lde_rows, width, limit, options.max_columns_per_batch)?
            };
            for columns in batches(width, capacity) {
                let source = all.len();
                if oracle == 2 && remaining > 0 {
                    let count = remaining.min(columns);
                    next.push(CoefficientBatch {
                        source,
                        columns: count,
                        first_opening: description.total() - remaining,
                        evaluation: PolynomialEvaluationPlan::prepare(
                            context,
                            kernels.clone(),
                            layout.degree,
                            count,
                            1,
                        )?,
                        combination: PolynomialCombinationPlan::prepare(
                            context,
                            kernels.clone(),
                            layout.degree,
                            count,
                            description.total() - remaining,
                            remaining != description.next,
                        )?,
                    });
                    remaining -= count;
                }
                all.push(CoefficientBatch {
                    source,
                    columns,
                    first_opening: first,
                    evaluation: PolynomialEvaluationPlan::prepare(
                        context,
                        kernels.clone(),
                        layout.degree,
                        columns,
                        0,
                    )?,
                    combination: PolynomialCombinationPlan::prepare(
                        context,
                        kernels.clone(),
                        layout.degree,
                        columns,
                        first,
                        first != 0,
                    )?,
                });
                first += columns;
            }
        }
        let division = [
            LinearDivisionPlan::prepare(context, kernels.clone(), layout.degree, 0)?,
            LinearDivisionPlan::prepare(context, kernels, layout.degree, 1)?,
        ];
        let mut eval_counts = Vec::<usize>::new();
        for batch in all.iter().chain(&next) {
            for (index, &count) in batch.evaluation.workspace_field_counts().iter().enumerate() {
                if index == eval_counts.len() {
                    eval_counts.push(count);
                } else {
                    eval_counts[index] = eval_counts[index].max(count);
                }
            }
        }
        let eval_scratch = eval_counts.len();
        let maximum_columns = all
            .iter()
            .map(|batch| batch.columns)
            .max()
            .context("empty opening oracle")?;
        let mut fields = vec![
            4,
            4,
            description.total() * 2,
            description.total() * 2,
            maximum_columns * 2,
            layout.degree * 2,
            layout.degree * 2,
            layout.lde_rows * 2,
        ];
        fields.extend(eval_counts);
        fields.extend_from_slice(division[0].workspace_field_counts());
        let source = format!(
            "{FIELD}\n{EXTENSION}\n{}",
            include_str!("../shaders/opening_parameters.wgsl").replace(
                "__SUBGROUP_GENERATOR__",
                &F::primitive_root_of_unity(common.degree_bits())
                    .to_canonical_u64()
                    .to_string()
            )
        );
        let specs = [write(2), read(4)];
        let points = PreparedKernel::prepare_entry(
            context,
            &source,
            &specs,
            "opening points",
            "points",
            true,
        )?;
        let weights = PreparedKernel::prepare_entry(
            context,
            &source,
            &specs,
            "opening weights",
            "weights",
            true,
        )?;
        let merge = PreparedKernel::prepare_entry(
            context,
            &format!(
                "{FIELD}\n{EXTENSION}\n{}",
                include_str!("../shaders/opening_merge.wgsl")
            ),
            &[write(2), read(2), read(4)],
            "FRI input accumulation",
            "main",
            true,
        )?;
        Ok(Self {
            params: context.prepare_params([
                description.all() as u32,
                description.next as u32,
                0,
                0,
            ])?,
            merge_params: [
                context.prepare_params([layout.degree as u32, description.all() as u32, 0, 0])?,
                context.prepare_params([layout.degree as u32, description.next as u32, 1, 0])?,
            ],
            layout: description,
            fields,
            all,
            next,
            division,
            points,
            weights,
            merge,
            eval_scratch,
        })
    }
}

/// Per-proof views for openings and the FRI input, in the caller's workspace.
pub struct OpeningBuffers<'c, 'a> {
    prepared: &'c PreparedCircuit<'a>,
    scalars: DeviceFieldSlice,
    points: DeviceFieldSlice,
    weights: DeviceFieldSlice,
    values: DeviceFieldSlice,
    batch_values: DeviceFieldSlice,
    composition: DeviceFieldSlice,
    fri_coefficients: DeviceFieldSlice,
    fri_evaluations: DeviceFieldSlice,
    evaluation_scratch: Vec<DeviceFieldSlice>,
    division_scratch: Vec<DeviceFieldSlice>,
}

/// Small opening values, interleaved extension pairs in CPU transcript order.
/// Borrows the original coefficient oracles for the subsequent FRI reduction.
/// Views pin workspace allocations and are overwritten on workspace reuse.
pub struct ResidentOpeningSet<'s> {
    pub values: DeviceFieldSlice,
    prepared: &'s PreparedOpenings,
    sources: Vec<FieldSource<'s>>,
    scalars: DeviceFieldSlice,
    points: DeviceFieldSlice,
}

/// Resident FRI input. Each buffer contains the real component plane followed
/// by the extension component plane. Evaluations are natural-order coset values.
/// Views pin workspace allocations and are overwritten on workspace reuse.
pub struct FriInput {
    pub coefficients: DeviceFieldSlice,
    pub evaluations: DeviceFieldSlice,
}

impl PreparedCircuit<'_> {
    pub fn opening_workspace_field_counts(&self) -> &[usize] {
        &self.openings.fields
    }

    pub fn opening_buffers(
        &self,
        workspace: &ProofWorkspace,
        first: usize,
    ) -> Result<OpeningBuffers<'_, '_>> {
        let buffers = workspace_views(workspace, first, &self.openings.fields)?;
        let division_start = 8 + self.openings.eval_scratch;
        Ok(OpeningBuffers {
            prepared: self,
            scalars: buffers[0].clone(),
            points: buffers[1].clone(),
            weights: buffers[2].clone(),
            values: buffers[3].clone(),
            batch_values: buffers[4].clone(),
            composition: buffers[5].clone(),
            fri_coefficients: buffers[6].clone(),
            fri_evaluations: buffers[7].clone(),
            evaluation_scratch: buffers[8..division_start].to_vec(),
            division_scratch: buffers[division_start..].to_vec(),
        })
    }
}

impl OpeningBuffers<'_, '_> {
    /// Encode polynomial evaluations after the quotient cap determines zeta.
    /// Reject subgroup points before encoding, as the CPU prover does.
    pub fn encode_openings<'s>(
        &'s self,
        encoder: &mut ProofEncoder<'_>,
        wires: &'s WireCommitment,
        permutation: &'s PermutationCommitment,
        quotient: &'s QuotientCommitment,
        zeta: E,
    ) -> Result<ResidentOpeningSet<'s>> {
        let sources = self
            .prepared
            .fixed
            .coefficients
            .iter()
            .map(FieldSource::from)
            .chain(wires.coefficients.iter().map(FieldSource::from))
            .chain(
                permutation
                    .oracle
                    .coefficients
                    .iter()
                    .map(FieldSource::from),
            )
            .chain(quotient.oracle.coefficients.iter().map(FieldSource::from))
            .collect::<Vec<_>>();
        self.encode_sources(encoder, sources, zeta)
    }

    fn encode_sources<'s>(
        &'s self,
        encoder: &mut ProofEncoder<'_>,
        sources: Vec<FieldSource<'s>>,
        zeta: E,
    ) -> Result<ResidentOpeningSet<'s>> {
        let plan = &self.prepared.openings;
        ensure!(
            zeta.exp_power_of_2(self.prepared.circuit.common.degree_bits()) != E::ONE,
            "Opening point is in the subgroup."
        );
        ensure!(
            sources.len() == plan.all.len()
                && sources
                    .iter()
                    .zip(&plan.all)
                    .all(|(source, batch)| source.len() == batch.columns * self.prepared.degree()),
            "opening oracle buffer shape mismatch"
        );
        encoder.upload(&self.scalars, &[zeta.0[0], zeta.0[1], F::ZERO, F::ZERO])?;
        let bindings = encoder.bind_with_params(
            &plan.points,
            &[
                FieldBinding::ReadWrite(&self.points),
                FieldBinding::Read((&self.scalars).into()),
            ],
            Some(&plan.params),
            "opening points",
        )?;
        encoder.dispatch(&plan.points, &bindings, [1, 1, 1], "opening points")?;
        for batch in plan.all.iter().chain(&plan.next) {
            let output = self.batch_values.slice(0..batch.columns * 2)?;
            batch.evaluation.encode(
                encoder,
                sources[batch.source],
                &self.points,
                &output,
                &self.evaluation_scratch,
            )?;
            encoder.copy(
                &output,
                &self
                    .values
                    .slice(batch.first_opening * 2..(batch.first_opening + batch.columns) * 2)?,
            )?;
        }
        Ok(ResidentOpeningSet {
            values: self.values.clone(),
            prepared: plan,
            sources,
            scalars: self.scalars.clone(),
            points: self.points.clone(),
        })
    }

    /// Alpha is supplied after the coordinator observes the opening values.
    /// Combine each opening batch, divide by its linear factor, shift prior
    /// batches with the CPU's alpha exponent, then evaluate the FRI input LDE.
    /// No coefficients or evaluations leave the device.
    pub fn encode_fri_input(
        &self,
        encoder: &mut ProofEncoder<'_>,
        openings: &ResidentOpeningSet<'_>,
        alpha: E,
    ) -> Result<FriInput> {
        let plan = &self.prepared.openings;
        ensure!(
            std::ptr::eq(plan, openings.prepared),
            "openings belong to another prepared circuit"
        );
        encoder.upload(&openings.scalars.slice(2..4)?, &alpha.0)?;
        let bindings = encoder.bind_with_params(
            &plan.weights,
            &[
                FieldBinding::ReadWrite(&self.weights),
                FieldBinding::Read((&openings.scalars).into()),
            ],
            Some(&plan.params),
            "opening weights",
        )?;
        encoder.dispatch_elements(
            &plan.weights,
            &bindings,
            plan.layout.total(),
            "opening weights",
        )?;
        for (index, batches) in [&plan.all, &plan.next].into_iter().enumerate() {
            for batch in batches {
                batch.combination.encode(
                    encoder,
                    openings.sources[batch.source],
                    &self.weights,
                    &self.composition,
                )?;
            }
            plan.division[index].encode(
                encoder,
                &self.composition,
                &openings.points,
                &self.composition,
                &self.division_scratch,
            )?;
            let bindings = encoder.bind_with_params(
                &plan.merge,
                &[
                    FieldBinding::ReadWrite(&self.fri_coefficients),
                    FieldBinding::Read((&self.composition).into()),
                    FieldBinding::Read((&openings.scalars).into()),
                ],
                Some(&plan.merge_params[index]),
                "FRI input accumulation",
            )?;
            encoder.dispatch_elements(
                &plan.merge,
                &bindings,
                self.prepared.degree(),
                "FRI input accumulation",
            )?;
        }
        self.prepared
            .forward
            .encode(encoder, &self.fri_coefficients, &self.fri_evaluations)?;
        Ok(FriInput {
            coefficients: self.fri_coefficients.clone(),
            evaluations: self.fri_evaluations.clone(),
        })
    }
}

impl ResidentOpeningSet<'_> {
    /// Explicit transcript export, after submission completion. Only the small
    /// opening vector is read back, never the coefficient or evaluation tables.
    pub fn readback(&self, context: &DeviceContext) -> Result<OpeningSet<F, 2>> {
        let layout = &self.prepared.layout;
        ensure!(
            self.values.len() == layout.total() * 2,
            "opening result buffer shape mismatch"
        );
        let values = context
            .readback(&self.values)?
            .chunks_exact(2)
            .map(|pair| QuadraticExtension([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let [fixed, wires, products, _] = layout.widths;
        Ok(OpeningSet {
            constants: values[..layout.constants].to_vec(),
            plonk_sigmas: values[layout.constants..fixed].to_vec(),
            wires: values[fixed..fixed + wires].to_vec(),
            plonk_zs: values[fixed + wires..fixed + wires + layout.next].to_vec(),
            partial_products: values[fixed + wires + layout.next..fixed + wires + products]
                .to_vec(),
            quotient_polys: values[fixed + wires + products..layout.all()].to_vec(),
            plonk_zs_next: values[layout.all()..].to_vec(),
            lookup_zs: Vec::new(),
            lookup_zs_next: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests;
