use super::oracle::workspace_views;
use super::*;
use crate::{
    MerkleQueryKernels, MerkleQueryLayout, MerkleQueryPlan, PowKernels, PowPlan, PowResult,
    ResidentMerkleQueries,
};
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::fri::proof::{FriInitialTreeProof, FriQueryRound, FriQueryStep};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::Challenger;

const POW_CHUNK_TRIALS: usize = 1 << 20;

pub(super) struct ProofTailLayout {
    initial: Vec<MerkleQueryLayout>,
    fri: Vec<(MerkleQueryLayout, usize)>,
    count: usize,
}

impl ProofTailLayout {
    pub fn new(
        common: &plonky2::plonk::circuit_data::CommonCircuitData<F, 2>,
        rows: usize,
        widths: [usize; 4],
        limit: u64,
    ) -> Result<Self> {
        crate::operations::validate_pow(
            common.config.fri_config.proof_of_work_bits,
            POW_CHUNK_TRIALS,
        )?;
        let count = common.config.fri_config.num_query_rounds;
        let cap = common.config.fri_config.cap_height;
        let initial = widths
            .into_iter()
            .map(|width| MerkleQueryLayout::new(rows, width, cap, count, 0))
            .collect::<Result<Vec<_>>>()?;
        let mut fri = Vec::new();
        let mut evaluations = rows;
        let mut shift = 0;
        // FriLayout has already validated these arities and domain sizes.
        for &bits in &common.fri_params.reduction_arity_bits {
            let arity = 1usize << bits;
            shift += bits;
            evaluations /= arity;
            fri.push((
                MerkleQueryLayout::new(evaluations, arity * 2, cap, count, shift)?,
                arity,
            ));
        }
        for layout in initial.iter().chain(fri.iter().map(|(layout, _)| layout)) {
            layout.validate_limit(limit)?;
        }
        Ok(Self {
            initial,
            fri,
            count,
        })
    }
}

pub(super) struct PreparedProofTail {
    pow: PowPlan,
    initial: Vec<MerkleQueryPlan>,
    fri: Vec<MerkleQueryPlan>,
    fields: Vec<usize>,
}

impl PreparedProofTail {
    pub fn prepare(
        context: &DeviceContext,
        circuit: &CircuitData<F, C, 2>,
        layout: &CircuitLayout,
        options: PreparationOptions,
        pow: Arc<PowKernels>,
        queries: Arc<MerkleQueryKernels>,
    ) -> Result<Self> {
        let pow = PowPlan::prepare(
            context,
            pow,
            circuit.common.config.fri_config.proof_of_work_bits,
            POW_CHUNK_TRIALS,
        )?;
        let limit = context
            .limits()
            .max_buffer_size
            .min(u64::from(context.limits().max_storage_buffer_binding_size));
        let mut initial = Vec::new();
        let widths = layout.openings.oracle_widths();
        for (index, &query_layout) in layout.proof_tail.initial.iter().enumerate() {
            let capacity = if index < 2 {
                layout.columns_per_batch
            } else {
                column_capacity(
                    layout.lde_rows,
                    widths[index],
                    limit,
                    options.max_columns_per_batch,
                )?
            };
            initial.push(MerkleQueryPlan::prepare_columns(
                context,
                queries.clone(),
                query_layout,
                &batches(widths[index], capacity),
            )?);
        }
        let fri = layout
            .proof_tail
            .fri
            .iter()
            .map(|&(layout, arity)| {
                MerkleQueryPlan::prepare_extension(context, queries.clone(), layout, arity)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut fields = pow.workspace_field_counts().to_vec();
        fields.push(layout.proof_tail.count);
        fields.extend(
            layout
                .proof_tail
                .initial
                .iter()
                .map(MerkleQueryLayout::field_count),
        );
        fields.extend(
            layout
                .proof_tail
                .fri
                .iter()
                .map(|(layout, _)| layout.field_count()),
        );
        Ok(Self {
            pow,
            initial,
            fri,
            fields,
        })
    }
}

/// Mutable proof-tail views. CPU owns transcript challenge generation; GPU
/// searches PoW nonces and gathers sampled proof data. Views pin allocations
/// and are overwritten on workspace reuse. Encoding never submits or reads back.
pub struct ProofTailBuffers<'c, 'a> {
    prepared: &'c PreparedCircuit<'a>,
    pow: [DeviceFieldSlice; 3],
    challenges: DeviceFieldSlice,
    initial: Vec<DeviceFieldSlice>,
    fri: Vec<DeviceFieldSlice>,
}

/// Only sampled leaves/paths, retained for final proof export. Views pin
/// workspace allocations and are overwritten on reuse.
pub struct ResidentQueryRounds {
    initial: Vec<ResidentMerkleQueries>,
    fri: Vec<ResidentMerkleQueries>,
}

impl PreparedCircuit<'_> {
    pub fn proof_tail_workspace_field_counts(&self) -> &[usize] {
        &self.proof_tail.fields
    }
    pub fn pow_chunk_trials(&self) -> usize {
        POW_CHUNK_TRIALS
    }

    pub fn proof_tail_buffers(
        &self,
        workspace: &ProofWorkspace,
        first: usize,
    ) -> Result<ProofTailBuffers<'_, '_>> {
        let buffers = workspace_views(workspace, first, &self.proof_tail.fields)?;
        Ok(ProofTailBuffers {
            prepared: self,
            pow: [buffers[0].clone(), buffers[1].clone(), buffers[2].clone()],
            challenges: buffers[3].clone(),
            initial: buffers[4..8].to_vec(),
            fri: buffers[8..].to_vec(),
        })
    }
}

impl ProofTailBuffers<'_, '_> {
    /// Encode one retryable chunk. Call PowResult::readback after completion to
    /// validate the nonce and advance the CPU transcript, or retry at a new base.
    pub fn encode_pow(
        &self,
        encoder: &mut ProofEncoder<'_>,
        challenger: &Challenger<F, PoseidonHash>,
        base: u64,
    ) -> Result<PowResult> {
        self.prepared.proof_tail.pow.encode(
            encoder,
            challenger,
            base,
            [&self.pow[0], &self.pow[1], &self.pow[2]],
        )
    }

    /// Challenges are supplied after consuming the PoW response. Gather the
    /// four original oracles and every FRI step, leaving full tables resident.
    pub fn encode_queries(
        &self,
        encoder: &mut ProofEncoder<'_>,
        challenges: &[F],
        wires: &WireCommitment,
        permutation: &PermutationCommitment,
        quotient: &QuotientCommitment,
        fri: &[FriCommitment],
    ) -> Result<ResidentQueryRounds> {
        let plan = &self.prepared.proof_tail;
        ensure!(
            challenges.len() == self.challenges.len() && fri.len() == plan.fri.len(),
            "proof query input count mismatch"
        );
        ensure!(
            fri.iter()
                .zip(&self.prepared.layout.proof_tail.fri)
                .all(|(commitment, (_, arity))| commitment.arity == *arity),
            "FRI query commitment arity mismatch"
        );
        encoder.upload(&self.challenges, challenges)?;
        let fixed = &self.prepared.fixed;
        let evaluations = [
            fixed
                .evaluations
                .iter()
                .map(FieldSource::from)
                .collect::<Vec<_>>(),
            wires.evaluations.iter().map(FieldSource::from).collect(),
            permutation
                .oracle
                .evaluations
                .iter()
                .map(FieldSource::from)
                .collect(),
            quotient
                .oracle
                .evaluations
                .iter()
                .map(FieldSource::from)
                .collect(),
        ];
        let trees = [
            FieldSource::from(&fixed.tree),
            (&wires.tree).into(),
            (&permutation.oracle.tree).into(),
            (&quotient.oracle.tree).into(),
        ];
        let mut initial = Vec::new();
        for (index, query_plan) in plan.initial.iter().enumerate() {
            initial.push(query_plan.encode(
                encoder,
                &self.challenges,
                &evaluations[index],
                trees[index],
                &self.initial[index],
            )?);
        }
        let mut steps = Vec::new();
        for ((query_plan, commitment), output) in plan.fri.iter().zip(fri).zip(&self.fri) {
            steps.push(query_plan.encode(
                encoder,
                &self.challenges,
                &[(&commitment.evaluations).into()],
                (&commitment.tree).into(),
                output,
            )?);
        }
        Ok(ResidentQueryRounds {
            initial,
            fri: steps,
        })
    }
}

impl ResidentQueryRounds {
    /// Explicit sparse export and CPU-format assembly after submission completion.
    pub fn readback(
        &self,
        context: &DeviceContext,
    ) -> Result<Vec<FriQueryRound<F, PoseidonHash, 2>>> {
        let initial = self
            .initial
            .iter()
            .map(|queries| queries.readback(context))
            .collect::<Result<Vec<_>>>()?;
        let fri = self
            .fri
            .iter()
            .map(|queries| queries.readback(context))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            initial.len() == 4,
            "proof query initial oracle count mismatch"
        );
        let count = initial[0].len();
        ensure!(
            initial
                .iter()
                .chain(&fri)
                .all(|queries| queries.len() == count),
            "proof query result count mismatch"
        );
        Ok((0..count)
            .map(|index| FriQueryRound {
                initial_trees_proof: FriInitialTreeProof {
                    evals_proofs: initial
                        .iter()
                        .map(|queries| queries[index].clone())
                        .collect(),
                },
                steps: fri
                    .iter()
                    .map(|queries| {
                        let (values, proof) = &queries[index];
                        FriQueryStep {
                            evals: values
                                .chunks_exact(2)
                                .map(|pair| QuadraticExtension([pair[0], pair[1]]))
                                .collect(),
                            merkle_proof: proof.clone(),
                        }
                    })
                    .collect(),
            })
            .collect())
    }
}
