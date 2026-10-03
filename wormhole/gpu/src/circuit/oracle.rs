use super::*;

/// Resident polynomial oracle in the same column and packed-tree order as
/// PolynomialBatch. Views pin workspace allocations and are overwritten on reuse.
pub struct PolynomialCommitment {
    pub coefficients: Vec<DeviceFieldSlice>,
    pub evaluations: Vec<DeviceFieldSlice>,
    pub tree: DeviceFieldSlice,
    pub cap: DeviceFieldSlice,
}

pub(super) struct OraclePlan {
    pub columns: Vec<usize>,
    pub fields: Vec<usize>,
    from_values: bool,
    commitment: CommitmentPlan,
}

impl OraclePlan {
    pub fn prepare(
        context: &DeviceContext,
        circuit: &CircuitData<F, C, 2>,
        layout: &CircuitLayout,
        options: PreparationOptions,
        kernels: Arc<PoseidonKernels>,
        width: usize,
        from_values: bool,
    ) -> Result<Self> {
        let capacity = column_capacity(
            layout.lde_rows,
            width,
            context
                .limits()
                .max_buffer_size
                .min(u64::from(context.limits().max_storage_buffer_binding_size)),
            options.max_columns_per_batch,
        )?;
        let columns = batches(width, capacity);
        let commitment = CommitmentPlan::prepare_chunked(
            context,
            kernels,
            layout.lde_rows,
            width,
            circuit.common.config.fri_config.cap_height,
            EvaluationOrder::BitReversed,
            options.commitment_chunk_rows,
        )?;
        let mut fields = Vec::new();
        for &count in &columns {
            if from_values {
                fields.push(layout.degree * count);
            }
            fields.extend([layout.degree * count, layout.lde_rows * count]);
        }
        fields.extend(commitment.workspace_field_counts());
        Ok(Self {
            columns,
            fields,
            from_values,
            commitment,
        })
    }

    pub fn buffers(&self, workspace: &ProofWorkspace, first: usize) -> Result<OracleBuffers> {
        let mut buffers = workspace_views(workspace, first, &self.fields)?.into_iter();
        let mut values = Vec::new();
        let mut coefficients = Vec::new();
        let mut evaluations = Vec::new();
        for _ in &self.columns {
            if self.from_values {
                values.push(buffers.next().unwrap());
            }
            coefficients.push(buffers.next().unwrap());
            evaluations.push(buffers.next().unwrap());
        }
        Ok(OracleBuffers {
            values,
            coefficients,
            evaluations,
            input_chunk: buffers.next().unwrap(),
            leaf_chunk: buffers.next().unwrap(),
            tree: buffers.next().unwrap(),
        })
    }

    pub fn encode_values(
        &self,
        prepared: &PreparedCircuit<'_>,
        encoder: &mut ProofEncoder<'_>,
        buffers: &OracleBuffers,
    ) -> Result<PolynomialCommitment> {
        for (values, coefficients) in buffers.values.iter().zip(&buffers.coefficients) {
            prepared.inverse.encode(encoder, values, coefficients)?;
        }
        self.encode_coefficients(prepared, encoder, buffers)
    }

    pub fn encode_coefficients(
        &self,
        prepared: &PreparedCircuit<'_>,
        encoder: &mut ProofEncoder<'_>,
        buffers: &OracleBuffers,
    ) -> Result<PolynomialCommitment> {
        for (coefficients, evaluations) in buffers.coefficients.iter().zip(&buffers.evaluations) {
            prepared
                .forward
                .encode(encoder, coefficients, evaluations)?;
        }
        let columns = buffers
            .evaluations
            .iter()
            .zip(&self.columns)
            .flat_map(|(batch, &columns)| {
                (0..columns).map(move |column| {
                    batch.slice(
                        column * prepared.layout.lde_rows..(column + 1) * prepared.layout.lde_rows,
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.commitment.encode(
            encoder,
            &columns.iter().map(FieldSource::from).collect::<Vec<_>>(),
            &buffers.input_chunk,
            &buffers.leaf_chunk,
            &buffers.tree,
        )?;
        Ok(PolynomialCommitment {
            coefficients: buffers.coefficients.clone(),
            evaluations: buffers.evaluations.clone(),
            tree: buffers.tree.clone(),
            cap: self.commitment.cap(&buffers.tree)?,
        })
    }
}

pub(super) struct OracleBuffers {
    pub values: Vec<DeviceFieldSlice>,
    pub coefficients: Vec<DeviceFieldSlice>,
    pub evaluations: Vec<DeviceFieldSlice>,
    input_chunk: DeviceFieldSlice,
    leaf_chunk: DeviceFieldSlice,
    tree: DeviceFieldSlice,
}

pub(super) fn workspace_views(
    workspace: &ProofWorkspace,
    first: usize,
    fields: &[usize],
) -> Result<Vec<DeviceFieldSlice>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, &len)| {
            let buffer = workspace.buffer(
                first
                    .checked_add(index)
                    .context("stage buffer index overflow")?,
            )?;
            ensure!(buffer.len() == len, "stage workspace buffer shape mismatch");
            Ok(buffer)
        })
        .collect()
}
