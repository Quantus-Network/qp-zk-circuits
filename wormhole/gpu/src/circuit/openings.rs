use super::oracle::workspace_views;
use super::*;
use crate::operations::{read, write, EXTENSION, FIELD};
use crate::runtime::KernelParams;
use crate::{
    ExtensionKernels, LinearDivisionPlan, PolynomialCombinationPlan, PolynomialEvaluationPlan,
};
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::fri::structure::{
    FriBatchInfo, FriCoefficient, FriInstanceInfo, FriOpeningExpression, FriOracleInfo,
    FriPolynomialInfo,
};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::plonk_common::PlonkOracle;
use plonky2::plonk::proof::OpeningSet;

type E = QuadraticExtension<F>;

#[derive(Clone, Copy)]
pub(super) struct OpeningLayout {
    oracle_widths: [usize; 4],
    constant_count: usize,
    next_row_opening_count: usize,
}

/// The verifier's FRI instance for `common` at `zeta`: the oracles and the
/// order in which every polynomial is opened at `zeta` and `g * zeta`. This
/// is `CommonCircuitData::get_fri_instance`, which the dependency keeps
/// crate-private; the pinned dependency version fixes the layout, and every
/// proof test verifies against that same verifier.
pub(crate) fn verifier_fri_instance(
    common: &CommonCircuitData<F, 2>,
    zeta: E,
) -> FriInstanceInfo<F, 2> {
    let num_preprocessed = common.sigmas_range().end;
    let num_zs_partial_products = common.config.num_challenges * (1 + common.num_partial_products);
    let num_lookup = common.config.num_challenges * common.num_lookup_polys;
    let num_quotient = common.config.num_challenges * common.quotient_degree_factor;
    let oracles = vec![
        FriOracleInfo {
            num_polys: num_preprocessed,
            blinding: PlonkOracle::CONSTANTS_SIGMAS.blinding,
        },
        FriOracleInfo {
            num_polys: common.config.num_wires,
            blinding: PlonkOracle::WIRES.blinding,
        },
        FriOracleInfo {
            num_polys: num_zs_partial_products + num_lookup,
            blinding: PlonkOracle::ZS_PARTIAL_PRODUCTS.blinding,
        },
        FriOracleInfo {
            num_polys: num_quotient,
            blinding: PlonkOracle::QUOTIENT.blinding,
        },
    ];
    let openings = |oracle: PlonkOracle, polynomials: core::ops::Range<usize>| {
        polynomials.map(move |polynomial_index| {
            FriOpeningExpression::raw(FriPolynomialInfo {
                oracle_index: oracle.index,
                polynomial_index,
            })
        })
    };
    let all = openings(PlonkOracle::CONSTANTS_SIGMAS, 0..num_preprocessed)
        .chain(openings(PlonkOracle::WIRES, 0..common.config.num_wires))
        .chain(openings(
            PlonkOracle::ZS_PARTIAL_PRODUCTS,
            0..num_zs_partial_products,
        ))
        .chain(openings(PlonkOracle::QUOTIENT, 0..num_quotient))
        .chain(openings(
            PlonkOracle::ZS_PARTIAL_PRODUCTS,
            num_zs_partial_products..num_zs_partial_products + num_lookup,
        ))
        .collect();
    let next = openings(PlonkOracle::ZS_PARTIAL_PRODUCTS, common.zs_range())
        .chain(openings(
            PlonkOracle::ZS_PARTIAL_PRODUCTS,
            num_zs_partial_products..num_zs_partial_products + num_lookup,
        ))
        .collect();
    let g = E::primitive_root_of_unity(common.degree_bits());
    FriInstanceInfo {
        oracles,
        batches: vec![
            FriBatchInfo {
                point: zeta,
                openings: all,
            },
            FriBatchInfo {
                point: g * zeta,
                openings: next,
            },
        ],
    }
}

impl OpeningLayout {
    pub fn new(common: &CommonCircuitData<F, 2>) -> Result<Self> {
        Self::from_instance(common, verifier_fri_instance(common, E::ONE))
    }

    fn from_instance(
        common: &CommonCircuitData<F, 2>,
        instance: FriInstanceInfo<F, 2>,
    ) -> Result<Self> {
        let oracle_widths = [
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
                    .zip(oracle_widths)
                    .all(|(oracle, width)| oracle.num_polys == width),
            "unsupported FRI opening oracle structure"
        );
        ensure!(
            instance.batches[0].point == E::ONE
                && instance.batches[1].point == E::primitive_root_of_unity(common.degree_bits()),
            "unsupported FRI opening points"
        );
        let expected = [
            oracle_widths
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
            oracle_widths,
            constant_count: common.num_constants,
            next_row_opening_count: common.config.num_challenges,
        })
    }

    pub(super) fn oracle_widths(&self) -> [usize; 4] {
        self.oracle_widths
    }

    fn zeta_opening_count(&self) -> usize {
        self.oracle_widths.iter().sum()
    }
    fn total_opening_count(&self) -> usize {
        self.zeta_opening_count() + self.next_row_opening_count
    }
}

struct CoefficientBatch {
    source_index: usize,
    columns: usize,
    first_opening: usize,
    evaluation: PolynomialEvaluationPlan,
    combination: PolynomialCombinationPlan,
}

pub(super) struct PreparedOpenings {
    layout: OpeningLayout,
    workspace_field_counts: Vec<usize>,
    zeta_batches: Vec<CoefficientBatch>,
    next_row_batches: Vec<CoefficientBatch>,
    division: [LinearDivisionPlan; 2],
    subgroup_generator: F,
    merge: PreparedKernel,
    merge_params: [KernelParams; 2],
    evaluation_scratch_buffer_count: usize,
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
        let mut zeta_batches = Vec::new();
        let mut next_row_batches = Vec::new();
        let mut first = 0;
        let mut remaining = description.next_row_opening_count;
        for (oracle, &width) in description.oracle_widths.iter().enumerate() {
            let capacity = if oracle < 2 {
                layout.columns_per_batch
            } else {
                column_capacity(layout.lde_rows, width, limit, options.max_columns_per_batch)?
            };
            for columns in batches(width, capacity) {
                let source_index = zeta_batches.len();
                if oracle == 2 && remaining > 0 {
                    let count = remaining.min(columns);
                    next_row_batches.push(CoefficientBatch {
                        source_index,
                        columns: count,
                        first_opening: description.total_opening_count() - remaining,
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
                            description.total_opening_count() - remaining,
                            remaining != description.next_row_opening_count,
                        )?,
                    });
                    remaining -= count;
                }
                zeta_batches.push(CoefficientBatch {
                    source_index,
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
        for batch in zeta_batches.iter().chain(&next_row_batches) {
            for (index, &count) in batch.evaluation.workspace_field_counts().iter().enumerate() {
                if index == eval_counts.len() {
                    eval_counts.push(count);
                } else {
                    eval_counts[index] = eval_counts[index].max(count);
                }
            }
        }
        let evaluation_scratch_buffer_count = eval_counts.len();
        let maximum_columns = zeta_batches
            .iter()
            .map(|batch| batch.columns)
            .max()
            .context("empty opening oracle")?;
        let mut workspace_field_counts = vec![
            4,
            description.total_opening_count() * 2,
            description.total_opening_count() * 2,
            maximum_columns * 2,
            layout.degree * 2,
            layout.degree * 2,
            layout.lde_rows * 2,
        ];
        workspace_field_counts.extend(eval_counts);
        workspace_field_counts.extend_from_slice(division[0].workspace_field_counts());
        let merge = PreparedKernel::prepare_entry(
            context,
            &format!(
                "{FIELD}\n{EXTENSION}\n{}",
                include_str!("../shaders/opening_merge.wgsl")
            ),
            &[write(2), read(2), read(2)],
            "FRI input accumulation",
            "main",
            true,
        )?;
        Ok(Self {
            merge_params: [
                context.prepare_params([layout.degree as u32, 0, 0, 0])?,
                context.prepare_params([
                    layout.degree as u32,
                    description.next_row_opening_count as u32,
                    1,
                    0,
                ])?,
            ],
            layout: description,
            workspace_field_counts,
            zeta_batches,
            next_row_batches,
            division,
            subgroup_generator: F::primitive_root_of_unity(common.degree_bits()),
            merge,
            evaluation_scratch_buffer_count,
        })
    }
}

/// Per-proof views for openings and the FRI input, in the caller's workspace.
pub struct OpeningBuffers<'c, 'a> {
    prepared: &'c PreparedCircuit<'a>,
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
        &self.openings.workspace_field_counts
    }

    pub fn opening_buffers(
        &self,
        workspace: &ProofWorkspace,
        first_buffer: usize,
    ) -> Result<OpeningBuffers<'_, '_>> {
        let buffers = workspace_views(
            workspace,
            first_buffer,
            &self.openings.workspace_field_counts,
        )?;
        let division_start = 7 + self.openings.evaluation_scratch_buffer_count;
        Ok(OpeningBuffers {
            prepared: self,
            points: buffers[0].clone(),
            weights: buffers[1].clone(),
            values: buffers[2].clone(),
            batch_values: buffers[3].clone(),
            composition: buffers[4].clone(),
            fri_coefficients: buffers[5].clone(),
            fri_evaluations: buffers[6].clone(),
            evaluation_scratch: buffers[7..division_start].to_vec(),
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
            sources.len() == plan.zeta_batches.len()
                && sources
                    .iter()
                    .zip(&plan.zeta_batches)
                    .all(|(source, batch)| source.len() == batch.columns * self.prepared.degree()),
            "opening oracle buffer shape mismatch"
        );
        let next = zeta.0.map(|component| component * plan.subgroup_generator);
        encoder.upload(&self.points, &[zeta.0[0], zeta.0[1], next[0], next[1]])?;
        for batch in plan.zeta_batches.iter().chain(&plan.next_row_batches) {
            let output = self.batch_values.slice(0..batch.columns * 2)?;
            batch.evaluation.encode(
                encoder,
                sources[batch.source_index],
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
        let mut weights = Vec::with_capacity(plan.layout.total_opening_count() * 2);
        for count in [
            plan.layout.zeta_opening_count(),
            plan.layout.next_row_opening_count,
        ] {
            let mut power = E::ONE;
            for _ in 0..count {
                weights.extend_from_slice(&power.0);
                power *= alpha;
            }
        }
        encoder.upload(&self.weights, &weights)?;
        for (index, batches) in [&plan.zeta_batches, &plan.next_row_batches]
            .into_iter()
            .enumerate()
        {
            for batch in batches {
                batch.combination.encode(
                    encoder,
                    openings.sources[batch.source_index],
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
                    FieldBinding::Read((&self.weights).into()),
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
            self.values.len() == layout.total_opening_count() * 2,
            "opening result buffer shape mismatch"
        );
        let values = context
            .readback(&self.values)?
            .chunks_exact(2)
            .map(|pair| QuadraticExtension([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let [fixed, wires, products, _] = layout.oracle_widths;
        Ok(OpeningSet {
            constants: values[..layout.constant_count].to_vec(),
            plonk_sigmas: values[layout.constant_count..fixed].to_vec(),
            wires: values[fixed..fixed + wires].to_vec(),
            plonk_zs: values[fixed + wires..fixed + wires + layout.next_row_opening_count].to_vec(),
            partial_products: values
                [fixed + wires + layout.next_row_opening_count..fixed + wires + products]
                .to_vec(),
            quotient_polys: values[fixed + wires + products..layout.zeta_opening_count()].to_vec(),
            plonk_zs_next: values[layout.zeta_opening_count()..].to_vec(),
            lookup_zs: Vec::new(),
            lookup_zs_next: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests;
