//! Host coordination in the same transcript order as plonky2's prover.
use super::*;
use plonky2::field::extension::quadratic::QuadraticExtension as E;
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::field::types::Field64;
use plonky2::fri::proof::FriProof;
use plonky2::fri::FriParamsObserve;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};

/// Six stage ranges in one per-proof workspace. Host metadata only;
/// constructing it never allocates GPU resources.
struct ProvingWorkspaceLayout {
    fields: Vec<usize>,
    first: [usize; 6],
}

impl ProvingWorkspaceLayout {
    fn new(stages: [&[usize]; 6]) -> Self {
        let mut fields = Vec::new();
        let first = stages.map(|stage| {
            let first = fields.len();
            fields.extend_from_slice(stage);
            first
        });
        Self { fields, first }
    }
}

impl PreparedCircuit<'_> {
    fn proving_workspace_layout(&self) -> ProvingWorkspaceLayout {
        ProvingWorkspaceLayout::new([
            self.wire_workspace_field_counts(),
            self.permutation_workspace_field_counts(),
            self.quotient_workspace_field_counts(),
            self.opening_workspace_field_counts(),
            self.fri_workspace_field_counts(),
            self.proof_tail_workspace_field_counts(),
        ])
    }

    /// Complete per-proof field-buffer plan, in stage order. This does not
    /// include shared fixed buffers, driver allocations or upload staging.
    pub fn proof_workspace_field_counts(&self) -> Vec<usize> {
        self.proving_workspace_layout().fields
    }

    /// Allocate once and reuse across proofs. Concurrent proofs require distinct
    /// workspaces; they can share this immutable prepared circuit and device.
    pub fn prepare_workspace(&self, context: &DeviceContext) -> Result<ProofWorkspace> {
        ProofWorkspace::prepare(context, &self.proof_workspace_field_counts())
    }

    /// Generate the remaining witness on CPU, then prove with resident GPU
    /// stages. This accepts PublicBatchProver::build_witness output; admission
    /// of private proofs remains the public-batch prover's responsibility.
    pub fn prove(
        &self,
        context: &DeviceContext,
        workspace: &mut ProofWorkspace,
        inputs: PartialWitness<F>,
    ) -> Result<ProofWithPublicInputs<F, C, 2>> {
        let partition = crate::profiling::measure("witness_generation", || {
            generate_partial_witness(inputs, &self.circuit.prover_only, &self.circuit.common)
                .context("generate proving witness")
        })?;
        self.prove_with_partition_witness(context, workspace, partition)
    }

    /// Blocking proof generation from a completed circuit witness. CPU owns
    /// the Fiat-Shamir transcript and proof assembly; large tables stay on GPU.
    /// All kernels/tables were prepared earlier. Only caps, status flags,
    /// openings, the final polynomial and sampled query data are read back.
    ///
    /// Waits for prior workspace work before reuse. An encoding or mathematical
    /// error leaves it reusable; device failure invalidates it. As with the CPU
    /// prover, callers verify the returned proof at their verification boundary.
    pub fn prove_with_partition_witness(
        &self,
        context: &DeviceContext,
        workspace: &mut ProofWorkspace,
        partition: PartitionWitness<'_, F>,
    ) -> Result<ProofWithPublicInputs<F, C, 2>> {
        let _proof = crate::profiling::HostOperation::new("gpu_prove");
        let layout = self.proving_workspace_layout();
        let [wfirst, pfirst, qfirst, ofirst, ffirst, tfirst] = layout.first;
        // Resolve and validate all stage views before recording any commands.
        let wires = self.wire_buffers(workspace, wfirst)?;
        let products = self.permutation_buffers(workspace, pfirst)?;
        let quotient = self.quotient_buffers(workspace, qfirst)?;
        let openings = self.opening_buffers(workspace, ofirst)?;
        let fri = self.fri_buffers(workspace, ffirst)?;
        let tail = self.proof_tail_buffers(workspace, tfirst)?;
        workspace.wait(context)?;

        let phase = enter_phase("wires", None);
        let mut encoder = workspace.begin(context)?;
        let wires = wires.encode_generated(&mut encoder, partition)?;
        encoder.submit()?.finish().context("commit witness wires")?;
        let wires_cap = read_cap(context, &wires.cap)?;

        let transcript = crate::profiling::HostOperation::new("transcript");
        let common = &self.circuit.common;
        let public_inputs_hash =
            <C as GenericConfig<2>>::InnerHasher::hash_no_pad(&wires.public_inputs);
        let mut challenger = Challenger::<F, <C as GenericConfig<2>>::Hasher>::new();
        common.fri_params.observe(&mut challenger);
        challenger.observe_hash::<<C as GenericConfig<2>>::Hasher>(
            self.circuit.prover_only.circuit_digest,
        );
        challenger.observe_hash::<<C as GenericConfig<2>>::InnerHasher>(public_inputs_hash);
        challenger.observe_cap::<<C as GenericConfig<2>>::Hasher>(&wires_cap);
        let betas = challenger.get_n_challenges(common.config.num_challenges);
        let gammas = challenger.get_n_challenges(common.config.num_challenges);
        drop(transcript);
        drop(phase);

        let phase = enter_phase("permutation", None);
        let mut encoder = workspace.begin(context)?;
        let products = products.encode(&mut encoder, &wires, &betas, &gammas)?;
        encoder
            .submit()?
            .finish()
            .context("commit permutation products")?;
        products.check_status(context)?;
        let products_cap = read_cap(context, &products.oracle.cap)?;
        let transcript = crate::profiling::HostOperation::new("transcript");
        challenger.observe_cap::<<C as GenericConfig<2>>::Hasher>(&products_cap);
        let alphas = challenger.get_n_challenges(common.config.num_challenges);
        drop(transcript);
        drop(phase);

        let phase = enter_phase("quotient", None);
        let mut encoder = workspace.begin(context)?;
        let quotient = quotient.encode(&mut encoder, &wires, &products, &alphas)?;
        encoder
            .submit()?
            .finish()
            .context("commit quotient polynomials")?;
        quotient.check_status(context)?;
        let quotient_cap = read_cap(context, &quotient.oracle.cap)?;
        let transcript = crate::profiling::HostOperation::new("transcript");
        challenger.observe_cap::<<C as GenericConfig<2>>::Hasher>(&quotient_cap);
        let zeta = challenger.get_extension_challenge::<2>();
        drop(transcript);
        drop(phase);

        let phase = enter_phase("openings", None);
        let mut encoder = workspace.begin(context)?;
        let resident_openings =
            openings.encode_openings(&mut encoder, &wires, &products, &quotient, zeta)?;
        encoder
            .submit()?
            .finish()
            .context("evaluate polynomial openings")?;
        let opening_set = resident_openings.readback(context)?;
        let transcript = crate::profiling::HostOperation::new("transcript");
        observe_openings(&mut challenger, &opening_set);
        let alpha = challenger.get_extension_challenge::<2>();
        drop(transcript);
        drop(phase);

        // Compose FRI-input generation with the first commitment. After each
        // cap, compose the fold with the next commitment in one submission.
        let phase = enter_phase("fri_input_and_first_commitment", None);
        let mut encoder = workspace.begin(context)?;
        let input = openings.encode_fri_input(&mut encoder, &resident_openings, alpha)?;
        let mut pending = if fri.round_count() > 0 {
            Some(
                fri.round(0)?
                    .encode_commitment(&mut encoder, &input.evaluations)?,
            )
        } else {
            None
        };
        encoder
            .submit()?
            .finish()
            .context("prepare FRI input and first commitment")?;
        drop(phase);
        let mut coefficients = input.coefficients;
        let mut commitments = Vec::with_capacity(fri.round_count());
        let mut caps = Vec::with_capacity(fri.round_count());
        for index in 0..fri.round_count() {
            let phase = enter_phase("fri_fold_and_next_commitment", Some(index));
            let commitment = pending.take().context("missing FRI round commitment")?;
            let cap = read_cap(context, &commitment.cap)?;
            let transcript = crate::profiling::HostOperation::new("transcript");
            challenger.observe_cap::<<C as GenericConfig<2>>::Hasher>(&cap);
            caps.push(cap);
            let beta = challenger.get_extension_challenge::<2>();
            drop(transcript);
            let mut encoder = workspace.begin(context)?;
            let folded = fri
                .round(index)?
                .encode_fold(&mut encoder, &coefficients, beta)?;
            pending = folded
                .evaluations
                .as_ref()
                .map(|evaluations| {
                    fri.round(index + 1)?
                        .encode_commitment(&mut encoder, evaluations)
                })
                .transpose()?;
            encoder
                .submit()?
                .finish()
                .context("fold FRI round and commit next layer")?;
            coefficients = folded.coefficients;
            commitments.push(commitment);
            drop(phase);
        }
        let phase = enter_phase("final_polynomial", None);
        let final_poly = read_final_poly(context, &coefficients)?;
        crate::profiling::measure("transcript", || {
            challenger.observe_extension_elements::<2>(&final_poly.coeffs)
        });
        drop(phase);

        let phase = enter_phase("pow", None);
        let mut base = 0;
        let mut chunks = 0u64;
        let pow_witness = loop {
            let mut encoder = workspace.begin(context)?;
            let result = tail.encode_pow(&mut encoder, &challenger, base)?;
            chunks += 1;
            encoder
                .submit()?
                .finish()
                .context("search FRI proof of work")?;
            if let Some(witness) = result.readback(context, &mut challenger)? {
                break witness;
            }
            base = next_pow_base(base, self.pow_chunk_trials())?;
        };
        tracing::debug!(target: "qp_wormhole_gpu::profile", pow_chunks = chunks,
            pow_trials_dispatched = chunks * self.pow_chunk_trials() as u64, "FRI grind");
        drop(phase);
        let challenges = crate::profiling::measure("transcript", || {
            challenger.get_n_challenges(common.config.fri_config.num_query_rounds)
        });
        let phase = enter_phase("queries", None);
        let mut encoder = workspace.begin(context)?;
        let queries = tail.encode_queries(
            &mut encoder,
            &challenges,
            &wires,
            &products,
            &quotient,
            &commitments,
        )?;
        encoder.submit()?.finish().context("gather proof queries")?;
        let query_round_proofs = queries.readback(context)?;
        drop(phase);
        let _assembly = crate::profiling::HostOperation::new("proof_assembly");
        Ok(ProofWithPublicInputs {
            public_inputs: wires.public_inputs,
            proof: Proof {
                wires_cap,
                plonk_zs_partial_products_cap: products_cap,
                quotient_polys_cap: quotient_cap,
                openings: opening_set,
                opening_proof: FriProof {
                    commit_phase_merkle_caps: caps,
                    query_round_proofs,
                    final_poly,
                    pow_witness,
                },
            },
        })
    }
}

fn enter_phase(name: &'static str, round: Option<usize>) -> crate::profiling::HostOperation {
    crate::profiling::HostOperation::phase(name, round)
}

fn next_pow_base(base: u64, trials: usize) -> Result<u64> {
    base.checked_add(trials as u64)
        .filter(|&base| base < F::ORDER)
        .context("FRI PoW exhausted the canonical nonce range")
}

fn observe_openings(
    challenger: &mut Challenger<F, <C as GenericConfig<2>>::Hasher>,
    openings: &OpeningSet<F, 2>,
) {
    // OpeningSet::to_fri_openings is private in the dependency. Match its two
    // batches without constructing temporary vectors; preparation rejects lookups.
    for values in [
        &openings.constants,
        &openings.plonk_sigmas,
        &openings.wires,
        &openings.plonk_zs,
        &openings.partial_products,
        &openings.quotient_polys,
        &openings.plonk_zs_next,
    ] {
        challenger.observe_extension_elements::<2>(values);
    }
}

fn read_cap(
    context: &DeviceContext,
    buffer: &DeviceFieldSlice,
) -> Result<MerkleCap<F, <C as GenericConfig<2>>::Hasher>> {
    let values = context.readback(buffer)?;
    ensure!(
        values.len() >= 4 && values.len().is_multiple_of(4),
        "invalid commitment cap shape"
    );
    Ok(MerkleCap(
        values
            .chunks_exact(4)
            .map(|chunk| HashOut {
                elements: [chunk[0], chunk[1], chunk[2], chunk[3]],
            })
            .collect(),
    ))
}

fn read_final_poly(
    context: &DeviceContext,
    buffer: &DeviceFieldSlice,
) -> Result<PolynomialCoeffs<E<F>>> {
    let values = context.readback(buffer)?;
    ensure!(
        !values.is_empty() && values.len().is_multiple_of(2),
        "invalid final polynomial shape"
    );
    let count = values.len() / 2;
    Ok(PolynomialCoeffs::new(
        (0..count)
            .map(|index| E([values[index], values[count + index]]))
            .collect(),
    ))
}

#[cfg(test)]
mod tests;
