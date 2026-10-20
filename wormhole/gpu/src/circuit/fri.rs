use super::oracle::workspace_views;
use super::*;
use crate::{FriCommitmentPlan, FriFoldPlan, FriKernels};
use plonky2::field::extension::quadratic::QuadraticExtension;

struct FriRoundLayout {
    coefficients: usize,
    evaluations: usize,
    arity: usize,
}

pub(super) struct FriLayout {
    rounds: Vec<FriRoundLayout>,
}

impl FriLayout {
    pub fn new(
        degree: usize,
        lde_rows: usize,
        arity_bits: &[usize],
        cap_height: usize,
        limit: u64,
    ) -> Result<Self> {
        ensure!(
            degree.is_power_of_two() && lde_rows.is_power_of_two() && degree <= lde_rows,
            "invalid FRI input shape"
        );
        ensure!(
            lde_rows <= u32::MAX as usize / 2 && lde_rows as u64 * 16 <= limit,
            "FRI buffers exceed storage-binding limit"
        );
        let mut coefficients = degree;
        let mut evaluations = lde_rows;
        let mut rounds = Vec::with_capacity(arity_bits.len());
        for &bits in arity_bits {
            let arity = u32::try_from(bits)
                .ok()
                .and_then(|bits| 1usize.checked_shl(bits))
                .context("FRI reduction arity overflow")?;
            ensure!(arity <= coefficients, "invalid FRI reduction arity");
            let leaves = evaluations / arity;
            ensure!(
                cap_height <= leaves.ilog2() as usize,
                "FRI cap exceeds leaf count"
            );
            let caps = 1usize << cap_height;
            let tree_fields = (2 * leaves - caps)
                .checked_mul(4)
                .context("FRI tree size overflow")?;
            ensure!(
                evaluations
                    .checked_mul(2)
                    .is_some_and(|n| n <= u32::MAX as usize && n as u64 * 8 <= limit)
                    && tree_fields <= u32::MAX as usize
                    && tree_fields as u64 * 8 <= limit,
                "FRI buffers exceed storage-binding limit"
            );
            rounds.push(FriRoundLayout {
                coefficients,
                evaluations,
                arity,
            });
            coefficients /= arity;
            evaluations = leaves;
        }
        // No reduction rounds is legal: the FRI input coefficients are already
        // the final polynomial, and no commitment/folding buffers are needed.
        Ok(Self { rounds })
    }
}

struct PreparedFriRound {
    fold: FriFoldPlan,
    commitment: FriCommitmentPlan,
    fft: Option<FftPlan>,
    arity: usize,
}

pub(super) struct PreparedFri {
    rounds: Vec<PreparedFriRound>,
    fields: Vec<usize>,
}

impl PreparedFri {
    pub fn prepare(
        context: &DeviceContext,
        circuit: &CircuitData<F, C, 2>,
        layout: &FriLayout,
        options: PreparationOptions,
        kernels: Arc<FriKernels>,
        poseidon: Arc<PoseidonKernels>,
        fft: Arc<FftKernels>,
    ) -> Result<Self> {
        let mut rounds = Vec::with_capacity(layout.rounds.len());
        let mut fields = Vec::new();
        let mut shift = F::MULTIPLICATIVE_GROUP_GENERATOR;
        for (index, round) in layout.rounds.iter().enumerate() {
            let fold =
                FriFoldPlan::prepare(context, kernels.clone(), round.coefficients, round.arity)?;
            let commitment = FriCommitmentPlan::prepare(
                context,
                kernels.clone(),
                poseidon.clone(),
                round.evaluations,
                round.arity,
                circuit.common.config.fri_config.cap_height,
                options.commitment_chunk_rows,
            )?;
            fields.extend([fold.output_field_count(), 2]);
            fields.extend(commitment.workspace_field_counts());
            shift = shift.exp_u64(round.arity as u64);
            let next_fft = if index + 1 < layout.rounds.len() {
                fields.push(2 * (round.evaluations / round.arity));
                Some(FftPlan::prepare_coset(
                    context,
                    fft.clone(),
                    round.coefficients / round.arity,
                    round.evaluations / round.arity,
                    shift,
                )?)
            } else {
                None
            };
            rounds.push(PreparedFriRound {
                fold,
                commitment,
                fft: next_fft,
                arity: round.arity,
            });
        }
        Ok(Self { rounds, fields })
    }
}

/// Per-proof FRI round views. The caller owns submission and cap observation;
/// these methods only encode resident operations and never export results.
/// Views pin workspace allocations and are overwritten on workspace reuse.
pub struct FriBuffers<'c> {
    rounds: Vec<FriRoundBuffers<'c>>,
}

/// Prepared operations and mutable views for one commit-then-fold round.
/// Views pin workspace allocations and are overwritten on workspace reuse.
pub struct FriRoundBuffers<'c> {
    prepared: &'c PreparedFriRound,
    coefficients: DeviceFieldSlice,
    beta: DeviceFieldSlice,
    input_chunk: DeviceFieldSlice,
    leaf_chunk: DeviceFieldSlice,
    tree: DeviceFieldSlice,
    evaluations: Option<DeviceFieldSlice>,
}

/// Grouped bit-reversed leaves committed in a resident packed tree. Evaluations
/// themselves stay natural-order real/extension planes for later query gathering.
/// Views pin workspace allocations and are overwritten on workspace reuse.
pub struct FriCommitment {
    pub evaluations: DeviceFieldSlice,
    pub tree: DeviceFieldSlice,
    pub cap: DeviceFieldSlice,
    pub arity: usize,
}

/// Resident result of one coefficient fold. No known-zero LDE padding is stored
/// in coefficients. Evaluations are natural-order component planes for the next
/// commitment, or None for the last round, whose coefficients are the final poly.
/// Views pin workspace allocations and are overwritten on workspace reuse.
pub struct FriFold {
    pub coefficients: DeviceFieldSlice,
    pub evaluations: Option<DeviceFieldSlice>,
}

impl PreparedCircuit<'_> {
    pub fn fri_workspace_field_counts(&self) -> &[usize] {
        &self.fri.fields
    }

    pub fn fri_buffers(&self, workspace: &ProofWorkspace, first: usize) -> Result<FriBuffers<'_>> {
        let mut buffers = workspace_views(workspace, first, &self.fri.fields)?.into_iter();
        let rounds = self
            .fri
            .rounds
            .iter()
            .map(|prepared| FriRoundBuffers {
                prepared,
                coefficients: buffers.next().unwrap(),
                beta: buffers.next().unwrap(),
                input_chunk: buffers.next().unwrap(),
                leaf_chunk: buffers.next().unwrap(),
                tree: buffers.next().unwrap(),
                evaluations: prepared.fft.as_ref().map(|_| buffers.next().unwrap()),
            })
            .collect();
        Ok(FriBuffers { rounds })
    }
}

impl FriBuffers<'_> {
    pub fn round_count(&self) -> usize {
        self.rounds.len()
    }

    pub fn round(&self, index: usize) -> Result<&FriRoundBuffers<'_>> {
        self.rounds
            .get(index)
            .context("FRI round index out of range")
    }
}

impl FriRoundBuffers<'_> {
    /// Commit natural-order evaluations. Bit reversal and extension flattening
    /// occur only in bounded leaf packing; no second full evaluation table exists.
    pub fn encode_commitment(
        &self,
        encoder: &mut ProofEncoder<'_>,
        evaluations: &DeviceFieldSlice,
    ) -> Result<FriCommitment> {
        self.prepared.commitment.encode(
            encoder,
            evaluations,
            &self.input_chunk,
            &self.leaf_chunk,
            &self.tree,
        )?;
        Ok(FriCommitment {
            evaluations: evaluations.clone(),
            tree: self.tree.clone(),
            cap: self.prepared.commitment.cap(&self.tree)?,
            arity: self.prepared.arity,
        })
    }

    /// Supply beta only after observing this round's cap. Fold the coefficients
    /// and, unless terminal, evaluate on the coset raised to this round's arity.
    /// This stage does not observe caps, submit, wait, or perform readback.
    pub fn encode_fold(
        &self,
        encoder: &mut ProofEncoder<'_>,
        coefficients: &DeviceFieldSlice,
        beta: QuadraticExtension<F>,
    ) -> Result<FriFold> {
        encoder.upload(&self.beta, &beta.0)?;
        self.prepared
            .fold
            .encode(encoder, coefficients, &self.beta, &self.coefficients)?;
        if let (Some(fft), Some(evaluations)) = (&self.prepared.fft, &self.evaluations) {
            fft.encode(encoder, &self.coefficients, evaluations)?;
        }
        Ok(FriFold {
            coefficients: self.coefficients.clone(),
            evaluations: self.evaluations.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
