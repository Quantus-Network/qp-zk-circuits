use super::oracle::{workspace_views, OracleBuffers, OraclePlan};
use super::*;
use crate::operations::{read, write, FIELD};
use crate::runtime::KernelParams;
use crate::PrefixProductPlan;

pub(super) struct PreparedPermutation {
    pub fields: Vec<usize>,
    pub oracle: OraclePlan,
    init: PreparedKernel,
    fold: PreparedKernel,
    ratios: PreparedKernel,
    assemble: PreparedKernel,
    sigmas: Vec<FixedFieldSlice>,
    identities: FixedFieldSlice,
    fold_params: Vec<KernelParams>,
    row_params: KernelParams,
    assemble_params: Vec<KernelParams>,
    scan: PrefixProductPlan,
    challenges: usize,
}

impl PreparedPermutation {
    pub fn prepare(
        context: &DeviceContext,
        circuit: &CircuitData<F, C, 2>,
        layout: &CircuitLayout,
        options: PreparationOptions,
        kernels: Arc<PoseidonKernels>,
    ) -> Result<Self> {
        let common = &circuit.common;
        let challenges = common.config.num_challenges;
        let routed = common.config.num_routed_wires;
        let chunk_size = common.permutation_partial_product_degree();
        ensure!(
            challenges > 0 && chunk_size > 1 && common.k_is.len() == routed,
            "unsupported permutation metadata"
        );
        ensure!(chunk_size < routed,
            "single-chunk permutations are unsupported: GPU oracle assembly requires partial-product columns");
        let chunks = routed.div_ceil(chunk_size);
        ensure!(
            common.num_partial_products + 1 == chunks,
            "partial-product count mismatch"
        );
        ensure!(
            circuit.prover_only.subgroup.len() == layout.degree
                && circuit.prover_only.sigmas.len() == layout.degree
                && circuit
                    .prover_only
                    .sigmas
                    .iter()
                    .all(|row| row.len() == routed),
            "permutation fixed table shape mismatch"
        );
        let source = format!(
            "{FIELD}\n{}",
            include_str!("../shaders/permutation.wgsl")
                .replace("__CHUNKS__", &chunks.to_string())
                .replace("__CHUNK_SIZE__", &chunk_size.to_string())
        );
        let init = PreparedKernel::prepare_entry(
            context,
            &source,
            &[write(1)],
            "permutation factor initialization",
            "initialize",
            false,
        )?;
        // Each entry point has its own binding indices; unused global bindings
        // are excluded from its layout by wgpu's shader reflection.
        let fold_source = format!(
            "{FIELD}\n{}",
            include_str!("../shaders/permutation_fold.wgsl")
                .replace("__CHUNKS__", &chunks.to_string())
                .replace("__CHUNK_SIZE__", &chunk_size.to_string())
        );
        let fold = PreparedKernel::prepare_entry(
            context,
            &fold_source,
            &[write(1), read(1), read(1), read(1), read(challenges * 2)],
            "permutation numerator and denominator products",
            "main",
            true,
        )?;
        let ratios = PreparedKernel::prepare_entry(
            context,
            &source,
            &[write(1), write(1), write(1)],
            "permutation batched inversion",
            "ratios",
            true,
        )?;
        let assemble = PreparedKernel::prepare_entry(
            context,
            &format!(
                "{FIELD}\n{}",
                include_str!("../shaders/permutation_assemble.wgsl")
                    .replace("__CHUNKS__", &chunks.to_string())
            ),
            &[write(1), read(1), read(1)],
            "permutation oracle assembly",
            "main",
            true,
        )?;
        let mut identities = circuit.prover_only.subgroup.clone();
        identities.extend_from_slice(&common.k_is);
        let identities = context.prepare_fixed(&identities)?;
        let mut sigmas = Vec::new();
        let mut fold_params = Vec::new();
        let mut first = 0;
        for &columns in &layout.batch_columns {
            let count = columns.min(routed.saturating_sub(first));
            if count > 0 {
                let values = (first..first + count)
                    .flat_map(|column| {
                        circuit
                            .prover_only
                            .sigmas
                            .iter()
                            .map(move |row| row[column])
                    })
                    .collect::<Vec<_>>();
                sigmas.push(context.prepare_fixed(&values)?);
                fold_params.push(context.prepare_params([
                    layout.degree as u32,
                    columns as u32,
                    count as u32,
                    first as u32,
                ])?);
            }
            first += columns;
        }
        let scan = PrefixProductPlan::prepare(context, layout.degree, challenges)?;
        let oracle = OraclePlan::prepare(
            context,
            circuit,
            layout,
            options,
            kernels,
            challenges * chunks,
            true,
        )?;
        let mut fields = vec![
            challenges * 2,
            2 * chunks * challenges * layout.degree,
            challenges * layout.degree,
            challenges * layout.degree,
            1,
        ];
        fields.extend_from_slice(scan.workspace_field_counts());
        fields.extend_from_slice(&oracle.fields);
        let mut first = 0;
        let assemble_params = oracle
            .columns
            .iter()
            .map(|&columns| {
                let params = context.prepare_params([
                    layout.degree as u32,
                    challenges as u32,
                    first as u32,
                    columns as u32,
                ]);
                first += columns;
                params
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            fields,
            oracle,
            init,
            fold,
            ratios,
            assemble,
            sigmas,
            identities,
            fold_params,
            row_params: context.prepare_params([layout.degree as u32, challenges as u32, 0, 0])?,
            assemble_params,
            scan,
            challenges,
        })
    }
}

/// Per-proof views for generating and committing Z and partial products.
pub struct PermutationBuffers<'c, 'a> {
    prepared: &'c PreparedCircuit<'a>,
    challenges: DeviceFieldSlice,
    factors: DeviceFieldSlice,
    row_products: DeviceFieldSlice,
    zs: DeviceFieldSlice,
    status: DeviceFieldSlice,
    scan_scratch: Vec<DeviceFieldSlice>,
    oracle: OracleBuffers,
}

/// Z columns first, followed by challenge-major partial-product columns, as in
/// the CPU prover. Status stays resident; check it before returning a proof.
pub struct PermutationCommitment {
    pub oracle: PolynomialCommitment,
    pub values: Vec<DeviceFieldSlice>,
    status: DeviceFieldSlice,
    #[cfg(feature = "constraint-export")]
    pub(super) betas: Vec<F>,
    #[cfg(feature = "constraint-export")]
    pub(super) gammas: Vec<F>,
}

impl PermutationCommitment {
    /// Explicit host validation, after submission completion. A future final
    /// proof export can gather this one-field flag with other proof outputs.
    pub fn check_status(&self, context: &DeviceContext) -> Result<()> {
        ensure!(
            context.readback(&self.status)? == [F::ZERO],
            "permutation denominator is zero"
        );
        Ok(())
    }
}

impl<'a> PreparedCircuit<'a> {
    pub fn permutation_workspace_field_counts(&self) -> &[usize] {
        &self.permutation.fields
    }

    pub fn permutation_buffers(
        &self,
        workspace: &ProofWorkspace,
        first: usize,
    ) -> Result<PermutationBuffers<'_, 'a>> {
        let plan = &self.permutation;
        let buffers = workspace_views(workspace, first, &plan.fields)?;
        let scan_end = 5 + plan.scan.workspace_field_counts().len();
        Ok(PermutationBuffers {
            prepared: self,
            challenges: buffers[0].clone(),
            factors: buffers[1].clone(),
            row_products: buffers[2].clone(),
            zs: buffers[3].clone(),
            status: buffers[4].clone(),
            scan_scratch: buffers[5..scan_end].to_vec(),
            oracle: plan.oracle.buffers(workspace, first + scan_end)?,
        })
    }
}

impl PermutationBuffers<'_, '_> {
    /// Challenges are supplied by the transcript coordinator after observing
    /// the wire cap. No cap readback or challenge generation occurs here.
    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        wires: &WireCommitment,
        betas: &[F],
        gammas: &[F],
    ) -> Result<PermutationCommitment> {
        let prepared = self.prepared;
        let plan = &prepared.permutation;
        ensure!(
            betas.len() == plan.challenges && gammas.len() == plan.challenges,
            "permutation challenge count mismatch"
        );
        ensure!(
            wires.wire_values.len() == prepared.layout.batch_columns.len()
                && wires
                    .wire_values
                    .iter()
                    .zip(&prepared.layout.batch_columns)
                    .all(|(buffer, &columns)| buffer.len() == prepared.layout.degree * columns),
            "permutation wire buffer shape mismatch"
        );
        encoder.upload(&self.challenges, &[betas, gammas].concat())?;
        encoder.upload(&self.status, &[F::ZERO])?;
        let group = encoder.bind(
            &plan.init,
            &[FieldBinding::ReadWrite(&self.factors)],
            "permutation factor initialization",
        )?;
        encoder.dispatch_elements(
            &plan.init,
            &group,
            self.factors.len(),
            "permutation factor initialization",
        )?;
        for ((wires, sigmas), params) in wires
            .wire_values
            .iter()
            .zip(&plan.sigmas)
            .zip(&plan.fold_params)
        {
            let group = encoder.bind_with_params(
                &plan.fold,
                &[
                    FieldBinding::ReadWrite(&self.factors),
                    FieldBinding::Read(wires.into()),
                    FieldBinding::Read(sigmas.into()),
                    FieldBinding::Read((&plan.identities).into()),
                    FieldBinding::Read((&self.challenges).into()),
                ],
                Some(params),
                "permutation numerator and denominator products",
            )?;
            encoder.dispatch_elements(
                &plan.fold,
                &group,
                prepared.layout.degree * plan.challenges,
                "permutation numerator and denominator products",
            )?;
        }
        let group = encoder.bind_with_params(
            &plan.ratios,
            &[
                FieldBinding::ReadWrite(&self.factors),
                FieldBinding::ReadWrite(&self.row_products),
                FieldBinding::ReadWrite(&self.status),
            ],
            Some(&plan.row_params),
            "permutation batched inversion",
        )?;
        encoder.dispatch_elements(
            &plan.ratios,
            &group,
            prepared.layout.degree * plan.challenges,
            "permutation batched inversion",
        )?;
        plan.scan
            .encode(encoder, &self.row_products, &self.zs, &self.scan_scratch)?;
        for (values, params) in self.oracle.values.iter().zip(&plan.assemble_params) {
            let group = encoder.bind_with_params(
                &plan.assemble,
                &[
                    FieldBinding::ReadWrite(values),
                    FieldBinding::Read((&self.factors).into()),
                    FieldBinding::Read((&self.zs).into()),
                ],
                Some(params),
                "permutation oracle assembly",
            )?;
            encoder.dispatch_elements(
                &plan.assemble,
                &group,
                values.len(),
                "permutation oracle assembly",
            )?;
        }
        Ok(PermutationCommitment {
            oracle: plan.oracle.encode_values(prepared, encoder, &self.oracle)?,
            values: self.oracle.values.clone(),
            status: self.status.clone(),
            #[cfg(feature = "constraint-export")]
            betas: betas.to_vec(),
            #[cfg(feature = "constraint-export")]
            gammas: gammas.to_vec(),
        })
    }
}
