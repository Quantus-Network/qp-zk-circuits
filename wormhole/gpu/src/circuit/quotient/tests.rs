use super::*;
use plonky2::field::extension::quadratic::QuadraticExtension as E;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::PrimeField64;
use plonky2::fri::proof::FriProof;
use plonky2::fri::structure::{FriOpeningBatch, FriOpenings};
use plonky2::fri::{FriChallenger, FriParamsObserve, FriReductionStrategy};
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::merkle_tree::{MerkleCap, MerkleTree};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::Challenger;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::plonk_common::reduce_with_powers_multi;
use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
use plonky2::plonk::prover::prove_with_partition_witness;
use plonky2::plonk::vars::EvaluationVarsBaseBatch;
use plonky2::util::reducing::ReducingFactor;
use plonky2::util::reverse_index_bits_in_place;
use plonky2::util::timing::TimingTree;

#[test]
fn quotient_chunks_fit_bindings_and_tile_the_domain() -> Result<()> {
    assert_eq!(chunk_capacity(128, 203, 203 * 8 * 17, 100)?, 16);
    assert_eq!(chunk_capacity(128, 203, u64::MAX, 7)?, 4);
    assert_eq!(chunk_capacity(128, 203, u64::MAX, 1024)?, 128);
    assert!(chunk_capacity(128, 203, 203 * 8 - 1, 100).is_err());
    assert!(chunk_capacity(128, 203, u64::MAX, 0).is_err());
    Ok(())
}

fn read_batches(context: &DeviceContext, buffers: &[DeviceFieldSlice]) -> Result<Vec<F>> {
    Ok(buffers
        .iter()
        .map(|buffer| context.readback(buffer))
        .collect::<Result<Vec<_>>>()?
        .concat())
}

fn assert_oracle(
    context: &DeviceContext,
    gpu: &PolynomialCommitment,
    cpu: &PolynomialBatch<F, C, 2>,
    rows: usize,
) -> Result<()> {
    assert_eq!(
        read_batches(context, &gpu.coefficients)?,
        cpu.polynomials
            .iter()
            .flat_map(|p| p.coeffs.iter().copied())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        read_batches(context, &gpu.evaluations)?,
        (0..cpu.polynomials.len())
            .flat_map(|column| (0..rows).map(move |row| cpu.get_lde_values(row, 1)[column]))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        context.readback(&gpu.tree)?,
        cpu.merkle_tree
            .digests
            .iter()
            .chain(&cpu.merkle_tree.cap.0)
            .flat_map(|hash| hash.elements)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        context.readback(&gpu.cap)?,
        cpu.merkle_tree
            .cap
            .0
            .iter()
            .flat_map(|hash| hash.elements)
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// Independent, straightforward recurrence over CPU MatrixWitness values.
/// The real CPU prover's caps are also compared below, so this is not the sole
/// oracle for ordering, challenge scheduling, or quotient semantics.
fn cpu_products(
    circuit: &CircuitData<F, C, 2>,
    wires: &[Vec<F>],
    betas: &[F],
    gammas: &[F],
) -> Vec<Vec<F>> {
    let common = &circuit.common;
    let count = common.num_partial_products;
    let c = betas.len();
    let mut values = vec![vec![F::ZERO; common.degree()]; c * (count + 1)];
    for challenge in 0..c {
        let mut z = F::ONE;
        for (row, &x) in circuit.prover_only.subgroup.iter().enumerate() {
            values[challenge][row] = z;
            let mut accumulator = z;
            for chunk in 0..=count {
                let start = chunk * common.permutation_partial_product_degree();
                let end = ((chunk + 1) * common.permutation_partial_product_degree())
                    .min(common.config.num_routed_wires);
                for (column, wire) in wires.iter().enumerate().take(end).skip(start) {
                    let numerator =
                        wire[row] + betas[challenge] * common.k_is[column] * x + gammas[challenge];
                    let denominator = wire[row]
                        + betas[challenge] * circuit.prover_only.sigmas[row][column]
                        + gammas[challenge];
                    accumulator *= numerator / denominator;
                }
                if chunk < count {
                    values[c + challenge * count + chunk][row] = accumulator;
                }
            }
            z = accumulator;
        }
        assert_eq!(
            z,
            F::ONE,
            "valid witness must close its permutation product"
        );
    }
    values
}

fn cpu_quotient_values(
    circuit: &CircuitData<F, C, 2>,
    wires: &PolynomialBatch<F, C, 2>,
    products: &PolynomialBatch<F, C, 2>,
    hash: &plonky2::hash::hash_types::HashOut<F>,
    betas: &[F],
    gammas: &[F],
    alphas: &[F],
) -> Vec<F> {
    let common = &circuit.common;
    let qrows = common.degree() * common.quotient_degree_factor.next_power_of_two();
    let step = common.lde_size() / qrows;
    let c = betas.len();
    let constants = &circuit.prover_only.constants_sigmas_commitment;
    let zero = ZeroPolyOnCoset::<F>::new(
        common.degree_bits(),
        (qrows / common.degree()).ilog2() as usize,
    );
    let root = F::primitive_root_of_unity(qrows.ilog2() as usize);
    let mut values = vec![F::ZERO; c * qrows];
    for (row, point) in root.powers().take(qrows).enumerate() {
        let x = F::coset_shift() * point;
        let fixed = constants.get_lde_values(row, step);
        let local_wires = wires.get_lde_values(row, step);
        let local = products.get_lde_values(row, step);
        let next = products.get_lde_values((row + qrows / common.degree()) % qrows, step);
        let vars =
            EvaluationVarsBaseBatch::new(1, &fixed[common.constants_range()], local_wires, hash);
        let mut gates = vec![F::ZERO; common.num_gate_constraints];
        for (i, gate) in common.gates.iter().enumerate() {
            let selector = common.selectors_info.selector_indices[i];
            for (sum, term) in gates.iter_mut().zip(gate.0.eval_filtered_base_batch(
                vars,
                i,
                selector,
                common.selectors_info.groups[selector].clone(),
                common.selectors_info.num_selectors(),
                0,
            )) {
                *sum += term;
            }
        }
        let mut terms = (0..c)
            .map(|challenge| zero.eval_l_0(row, x) * (local[challenge] - F::ONE))
            .collect::<Vec<_>>();
        for challenge in 0..c {
            for chunk in 0..=common.num_partial_products {
                let columns = chunk * common.permutation_partial_product_degree()
                    ..((chunk + 1) * common.permutation_partial_product_degree())
                        .min(common.config.num_routed_wires);
                let numerator: F = columns
                    .clone()
                    .map(|j| {
                        local_wires[j] + betas[challenge] * common.k_is[j] * x + gammas[challenge]
                    })
                    .product();
                let denominator: F = columns
                    .map(|j| {
                        local_wires[j]
                            + betas[challenge] * fixed[common.num_constants + j]
                            + gammas[challenge]
                    })
                    .product();
                let previous = if chunk == 0 {
                    local[challenge]
                } else {
                    local[c + challenge * common.num_partial_products + chunk - 1]
                };
                let following = if chunk == common.num_partial_products {
                    next[challenge]
                } else {
                    local[c + challenge * common.num_partial_products + chunk]
                };
                terms.push(previous * numerator - following * denominator);
            }
        }
        terms.extend(gates);
        for (challenge, quotient) in reduce_with_powers_multi(&terms, alphas)
            .into_iter()
            .enumerate()
        {
            values[challenge * qrows + row] = quotient * zero.eval_inverse(row);
        }
    }
    values
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn resident_proving_stages_match_cpu_and_generate_verifiable_proofs() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    for (challenges, factor, rate) in [(2, 8, 3), (3, 7, 4)] {
        let mut config = CircuitConfig::standard_recursion_config();
        config.num_challenges = challenges;
        config.max_quotient_degree_factor = factor;
        config.fri_config.rate_bits = rate;
        // A tiny proof is an independent CPU oracle, not an arity benchmark.
        config.fri_config.proof_of_work_bits = 8;
        // Two rounds exercise fold -> next commitment scheduling and shifted
        // query gathering instead of only the final-fold special case.
        config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![2, 2]);
        config.security_bits = 80;
        let mut builder = CircuitBuilder::<F, 2>::new(config);
        let input = builder.add_virtual_target();
        let duplicate = builder.add_virtual_target();
        builder.connect(input, duplicate);
        let square = builder.mul(input, duplicate);
        builder.register_public_input(square);
        for _ in 0..257 {
            builder.add_gate(NoopGate, vec![]);
        }
        let circuit = builder.build::<C>();
        let common = &circuit.common;
        assert_eq!(common.quotient_degree_factor, factor);
        let prepared = PreparedCircuit::prepare(
            &context,
            &circuit,
            PreparationOptions {
                max_columns_per_batch: 17,
                commitment_chunk_rows: 128,
                quotient_chunk_rows: 257,
            },
        )?;
        let mut counts = prepared.wire_workspace_field_counts().to_vec();
        let pfirst = counts.len();
        counts.extend_from_slice(prepared.permutation_workspace_field_counts());
        let qfirst = counts.len();
        counts.extend_from_slice(prepared.quotient_workspace_field_counts());
        let ofirst = counts.len();
        counts.extend_from_slice(prepared.opening_workspace_field_counts());
        let ffirst = counts.len();
        counts.extend_from_slice(prepared.fri_workspace_field_counts());
        let tfirst = counts.len();
        counts.extend_from_slice(prepared.proof_tail_workspace_field_counts());
        let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
        let wire_buffers = prepared.wire_buffers(&workspace, 0)?;
        let product_buffers = prepared.permutation_buffers(&workspace, pfirst)?;
        let quotient_buffers = prepared.quotient_buffers(&workspace, qfirst)?;
        let opening_buffers = prepared.opening_buffers(&workspace, ofirst)?;
        let fri_buffers = prepared.fri_buffers(&workspace, ffirst)?;
        let tail_buffers = prepared.proof_tail_buffers(&workspace, tfirst)?;
        let mut inputs = PartialWitness::new();
        inputs.set_target(input, F::NEG_ONE)?;
        let partition = generate_partial_witness(inputs, &circuit.prover_only, common)?;
        let cpu_proof = prove_with_partition_witness(
            &circuit.prover_only,
            common,
            partition.clone(),
            &mut TimingTree::default(),
        )?;
        circuit.verify(cpu_proof.clone())?;
        let coordinator_witness = partition.clone();
        let full_witness = partition.clone().full_witness();
        let wire_values = (0..common.config.num_wires)
            .map(|column| {
                (0..common.degree())
                    .map(|row| full_witness.get_wire(row, column))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let cpu_wires = PolynomialBatch::<F, C, 2>::from_values(
            wire_values
                .iter()
                .cloned()
                .map(PolynomialValues::new)
                .collect(),
            rate,
            false,
            common.config.fri_config.cap_height,
            &mut TimingTree::default(),
            circuit.prover_only.fft_root_table.as_ref(),
        );
        assert_eq!(cpu_wires.merkle_tree.cap, cpu_proof.proof.wires_cap);
        let hash = <C as GenericConfig<2>>::InnerHasher::hash_no_pad(&cpu_proof.public_inputs);
        let mut challenger = Challenger::<F, PoseidonHash>::new();
        common.fri_params.observe(&mut challenger);
        challenger.observe_hash::<PoseidonHash>(circuit.prover_only.circuit_digest);
        challenger.observe_hash::<PoseidonHash>(hash);
        challenger.observe_cap::<PoseidonHash>(&cpu_wires.merkle_tree.cap);
        let betas = challenger.get_n_challenges(challenges);
        let gammas = challenger.get_n_challenges(challenges);
        let product_values = cpu_products(&circuit, &wire_values, &betas, &gammas);
        let cpu_products = PolynomialBatch::<F, C, 2>::from_values(
            product_values
                .iter()
                .cloned()
                .map(PolynomialValues::new)
                .collect(),
            rate,
            false,
            common.config.fri_config.cap_height,
            &mut TimingTree::default(),
            circuit.prover_only.fft_root_table.as_ref(),
        );
        assert_eq!(
            cpu_products.merkle_tree.cap,
            cpu_proof.proof.plonk_zs_partial_products_cap
        );
        challenger.observe_cap::<PoseidonHash>(&cpu_products.merkle_tree.cap);
        let alphas = challenger.get_n_challenges(challenges);
        let mut encoder = workspace.begin(&context)?;
        let wires = wire_buffers.encode_generated(&mut encoder, partition)?;
        assert!(product_buffers
            .encode(&mut encoder, &wires, &[], &gammas)
            .is_err());
        let products = product_buffers.encode(&mut encoder, &wires, &betas, &gammas)?;
        assert!(quotient_buffers
            .encode(&mut encoder, &wires, &products, &[])
            .is_err());
        let quotient = quotient_buffers.encode(&mut encoder, &wires, &products, &alphas)?;
        // Fixed oracle, wires, products, quotient share one encoder/submission.
        // Challenge values come from the independent CPU oracle, not readback.
        encoder.submit()?.finish()?;
        products.check_status(&context)?;
        quotient.check_status(&context)?;
        assert_eq!(
            read_batches(&context, &products.values)?,
            product_values.concat()
        );
        assert_oracle(
            &context,
            &products.oracle,
            &cpu_products,
            prepared.evaluation_rows(),
        )?;
        let expected_values = cpu_quotient_values(
            &circuit,
            &cpu_wires,
            &cpu_products,
            &hash,
            &betas,
            &gammas,
            &alphas,
        );
        assert_eq!(
            context.readback(&quotient.full_evaluations)?,
            expected_values
        );
        let coefficients = expected_values
            .chunks(prepared.quotient_rows())
            .map(|values| PolynomialValues::new(values.to_vec()).coset_ifft(F::coset_shift()))
            .collect::<Vec<_>>();
        assert_eq!(
            context.readback(&quotient.full_coefficients)?,
            coefficients
                .iter()
                .flat_map(|p| p.coeffs.iter().copied())
                .collect::<Vec<_>>()
        );
        let chunks = coefficients
            .into_iter()
            .flat_map(|mut p| {
                p.trim_to_len(common.quotient_degree()).unwrap();
                p.chunks(common.degree())
            })
            .collect::<Vec<PolynomialCoeffs<F>>>();
        let cpu_quotient = PolynomialBatch::<F, C, 2>::from_coeffs(
            chunks,
            rate,
            false,
            common.config.fri_config.cap_height,
            &mut TimingTree::default(),
            None,
        );
        assert_eq!(
            cpu_quotient.merkle_tree.cap,
            cpu_proof.proof.quotient_polys_cap
        );
        assert_oracle(
            &context,
            &quotient.oracle,
            &cpu_quotient,
            prepared.evaluation_rows(),
        )?;
        challenger.observe_cap::<PoseidonHash>(&cpu_quotient.merkle_tree.cap);
        let zeta = challenger.get_extension_challenge::<2>();
        let g = E::<F>::primitive_root_of_unity(common.degree_bits());
        let cpu_openings = OpeningSet::new(
            zeta,
            g,
            &circuit.prover_only.constants_sigmas_commitment,
            &cpu_wires,
            &cpu_products,
            &cpu_quotient,
            common,
        );
        assert_eq!(cpu_openings, cpu_proof.proof.openings);
        let mut encoder = workspace.begin(&context)?;
        assert_eq!(
            opening_buffers
                .encode_openings(&mut encoder, &wires, &products, &quotient, E::<F>::ONE)
                .err()
                .unwrap()
                .to_string(),
            "Opening point is in the subgroup."
        );
        let openings =
            opening_buffers.encode_openings(&mut encoder, &wires, &products, &quotient, zeta)?;
        encoder.submit()?.finish()?;
        let gpu_openings = openings.readback(&context)?;
        assert_eq!(gpu_openings, cpu_openings);
        challenger.observe_openings(&FriOpenings::<F, 2> {
            batches: vec![
                FriOpeningBatch {
                    values: [
                        gpu_openings.constants,
                        gpu_openings.plonk_sigmas,
                        gpu_openings.wires,
                        gpu_openings.plonk_zs,
                        gpu_openings.partial_products,
                        gpu_openings.quotient_polys,
                    ]
                    .concat(),
                },
                FriOpeningBatch {
                    values: gpu_openings.plonk_zs_next,
                },
            ],
        });
        let alpha = challenger.get_extension_challenge::<2>();
        let mut encoder = workspace.begin(&context)?;
        let fri_input = opening_buffers.encode_fri_input(&mut encoder, &openings, alpha)?;
        encoder.submit()?.finish()?;
        let cpu_oracles = [
            &circuit.prover_only.constants_sigmas_commitment,
            &cpu_wires,
            &cpu_products,
            &cpu_quotient,
        ];
        let all = cpu_oracles
            .iter()
            .flat_map(|oracle| oracle.polynomials.iter().map(|p| p.to_extension::<2>()))
            .collect::<Vec<_>>();
        let next = cpu_products.polynomials[..challenges]
            .iter()
            .map(|p| p.to_extension::<2>())
            .collect::<Vec<_>>();
        let mut reduction = ReducingFactor::new(alpha);
        let mut combined = PolynomialCoeffs::empty();
        for (polynomials, point) in [(all, zeta), (next, g * zeta)] {
            let composition = reduction.reduce_polys(polynomials.iter());
            let mut quotient = composition.divide_by_linear(point);
            quotient.coeffs.push(E::<F>::ZERO);
            reduction.shift_poly(&mut combined);
            combined += quotient;
        }
        let planes = |values: &[E<F>]| {
            (0..2)
                .flat_map(|component| values.iter().map(move |value| value.0[component]))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            context.readback(&fri_input.coefficients)?,
            planes(&combined.coeffs)
        );
        let lde = combined
            .padded(common.lde_size())
            .coset_fft(E([F::coset_shift(), F::ZERO]));
        assert_eq!(
            context.readback(&fri_input.evaluations)?,
            planes(&lde.values)
        );
        // Anchor the independent reduction oracle to the real CPU proof's
        // first FRI cap, not only to a second implementation of the formula.
        let mut leaves = lde.values;
        reverse_index_bits_in_place(&mut leaves);
        let arity = 1 << common.fri_params.reduction_arity_bits[0];
        let tree = MerkleTree::<F, PoseidonHash>::new(
            leaves
                .chunks(arity)
                .map(|chunk| chunk.iter().flat_map(|value| value.0).collect())
                .collect(),
            common.config.fri_config.cap_height,
        );
        assert_eq!(
            tree.cap,
            cpu_proof.proof.opening_proof.commit_phase_merkle_caps[0]
        );
        // Follow the same transcript through every resident FRI round. The
        // CPU oracle retains LDE zero padding; the GPU omits it in coefficients.
        assert_eq!(
            fri_buffers.round_count(),
            common.fri_params.reduction_arity_bits.len()
        );
        assert_eq!(
            fri_buffers.round(usize::MAX).err().unwrap().to_string(),
            "FRI round index out of range"
        );
        let mut coefficients = fri_input.coefficients.clone();
        let evaluations = fri_input.evaluations.clone();
        let mut cpu_coefficients = combined.padded(common.lde_size());
        let mut coefficient_count = common.degree();
        let mut shift = F::MULTIPLICATIVE_GROUP_GENERATOR;
        let mut fri_commitments = Vec::new();
        let mut fri_caps = Vec::new();
        let mut encoder = workspace.begin(&context)?;
        let mut pending_commitment = Some(
            fri_buffers
                .round(0)?
                .encode_commitment(&mut encoder, &evaluations)?,
        );
        encoder.submit()?.finish()?;
        for (index, &bits) in common.fri_params.reduction_arity_bits.iter().enumerate() {
            let round = fri_buffers.round(index)?;
            let commitment = pending_commitment.take().unwrap();
            let cap = MerkleCap::<F, PoseidonHash>(
                context
                    .readback(&commitment.cap)?
                    .chunks_exact(4)
                    .map(|chunk| HashOut {
                        elements: chunk.try_into().unwrap(),
                    })
                    .collect(),
            );
            assert_eq!(
                cap,
                cpu_proof.proof.opening_proof.commit_phase_merkle_caps[index]
            );
            challenger.observe_cap::<PoseidonHash>(&cap);
            fri_caps.push(cap);
            let beta = challenger.get_extension_challenge::<2>();
            let arity = 1 << bits;
            assert_eq!(commitment.arity, arity);
            let mut encoder = workspace.begin(&context)?;
            let folded = round.encode_fold(&mut encoder, &coefficients, beta)?;
            // There is no transcript dependency between this fold and the
            // following commitment: submit both, then export only its cap.
            pending_commitment = folded
                .evaluations
                .as_ref()
                .map(|values| {
                    fri_buffers
                        .round(index + 1)?
                        .encode_commitment(&mut encoder, values)
                })
                .transpose()?;
            encoder.submit()?.finish()?;
            fri_commitments.push(commitment);
            cpu_coefficients = PolynomialCoeffs::new(
                cpu_coefficients
                    .coeffs
                    .chunks_exact(arity)
                    .map(|chunk| plonky2::plonk::plonk_common::reduce_with_powers(chunk, beta))
                    .collect(),
            );
            coefficient_count /= arity;
            assert!(cpu_coefficients.coeffs[coefficient_count..]
                .iter()
                .all(|value| *value == E::<F>::ZERO));
            assert_eq!(
                context.readback(&folded.coefficients)?,
                planes(&cpu_coefficients.coeffs[..coefficient_count])
            );
            coefficients = folded.coefficients;
            if let Some(next) = folded.evaluations {
                shift = shift.exp_u64(arity as u64);
                let expected = cpu_coefficients.coset_fft(E([shift, F::ZERO]));
                assert_eq!(context.readback(&next)?, planes(&expected.values));
            } else {
                assert_eq!(index + 1, fri_buffers.round_count());
            }
        }
        cpu_coefficients.coeffs.truncate(coefficient_count);
        assert_eq!(cpu_coefficients, cpu_proof.proof.opening_proof.final_poly);
        assert_eq!(
            context.readback(&coefficients)?,
            planes(&cpu_proof.proof.opening_proof.final_poly.coeffs)
        );
        let final_words = context.readback(&coefficients)?;
        let final_count = final_words.len() / 2;
        let final_poly = PolynomialCoeffs::new(
            (0..final_count)
                .map(|index| E([final_words[index], final_words[final_count + index]]))
                .collect(),
        );
        challenger.observe_extension_elements::<2>(&final_poly.coeffs);
        // A different nonce deliberately gives different query challenges.
        // Compare gathered paths to CPU trees at those actual GPU-proof indices,
        // then verify the assembled proof with the normal circuit verifier.
        let mut encoder = workspace.begin(&context)?;
        let pow = tail_buffers.encode_pow(&mut encoder, &challenger, 100)?;
        encoder.submit()?.finish()?;
        let pow_witness = pow.readback(&context, &mut challenger)?.unwrap();
        let query_challenges =
            challenger.get_n_challenges(common.config.fri_config.num_query_rounds);
        let mut encoder = workspace.begin(&context)?;
        assert!(tail_buffers
            .encode_queries(
                &mut encoder,
                &query_challenges[..query_challenges.len() - 1],
                &wires,
                &products,
                &quotient,
                &fri_commitments
            )
            .is_err());
        let queries = tail_buffers.encode_queries(
            &mut encoder,
            &query_challenges,
            &wires,
            &products,
            &quotient,
            &fri_commitments,
        )?;
        encoder.submit()?.finish()?;
        let query_round_proofs = queries.readback(&context)?;
        for (proof, challenge) in query_round_proofs.iter().zip(&query_challenges) {
            let index = challenge.to_canonical_u64() as usize % common.lde_size();
            let expected = cpu_oracles
                .iter()
                .map(|oracle| {
                    (
                        oracle.merkle_tree.get(index).to_vec(),
                        oracle.merkle_tree.prove(index),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(proof.initial_trees_proof.evals_proofs, expected);
        }
        let read_cap = |buffer: &DeviceFieldSlice| -> Result<MerkleCap<F, PoseidonHash>> {
            Ok(MerkleCap(
                context
                    .readback(buffer)?
                    .chunks_exact(4)
                    .map(|chunk| HashOut {
                        elements: chunk.try_into().unwrap(),
                    })
                    .collect(),
            ))
        };
        let mut gpu_proof = ProofWithPublicInputs::<F, C, 2> {
            public_inputs: wires.public_inputs.clone(),
            proof: Proof {
                wires_cap: read_cap(&wires.cap)?,
                plonk_zs_partial_products_cap: read_cap(&products.oracle.cap)?,
                quotient_polys_cap: read_cap(&quotient.oracle.cap)?,
                openings: openings.readback(&context)?,
                opening_proof: FriProof {
                    commit_phase_merkle_caps: fri_caps,
                    query_round_proofs,
                    final_poly,
                    pow_witness,
                },
            },
        };
        circuit.verify(gpu_proof.clone())?;
        // A malformed gathered sibling is not accepted by the CPU verifier.
        gpu_proof.proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1
            .siblings[0]
            .elements[0] += F::ONE;
        assert!(circuit.verify(gpu_proof).is_err());
        // Exercise the reusable coordinator with the same completed witness.
        // Unlike the diagnostic sequence above, its challenges come only from
        // GPU-produced caps and openings, never from the CPU proof oracle.
        let coordinated =
            prepared.prove_with_partition_witness(&context, &mut workspace, coordinator_witness)?;
        assert_eq!(coordinated.proof.wires_cap, cpu_proof.proof.wires_cap);
        assert_eq!(
            coordinated.proof.plonk_zs_partial_products_cap,
            cpu_proof.proof.plonk_zs_partial_products_cap
        );
        assert_eq!(
            coordinated.proof.quotient_polys_cap,
            cpu_proof.proof.quotient_polys_cap
        );
        assert_eq!(coordinated.proof.openings, cpu_proof.proof.openings);
        assert_eq!(
            coordinated.proof.opening_proof.commit_phase_merkle_caps,
            cpu_proof.proof.opening_proof.commit_phase_merkle_caps
        );
        assert_eq!(
            coordinated.proof.opening_proof.final_poly,
            cpu_proof.proof.opening_proof.final_poly
        );
        circuit.verify(coordinated)?;
        // Reuse the same prepared plans and workspace with zero alpha. This
        // changes the composition and catches stale weights/accumulation data.
        let mut encoder = workspace.begin(&context)?;
        let zero_input = opening_buffers.encode_fri_input(&mut encoder, &openings, E::<F>::ZERO)?;
        encoder.submit()?.finish()?;
        let mut zero_expected = cpu_products.polynomials[0]
            .to_extension::<2>()
            .divide_by_linear(g * zeta);
        zero_expected.coeffs.push(E::<F>::ZERO);
        assert_eq!(
            context.readback(&zero_input.coefficients)?,
            planes(&zero_expected.coeffs)
        );
        // Reuse the stage allocations without re-preparing pipelines. A zero
        // denominator must set the resident flag, not disappear via inverse(0).
        let mut encoder = workspace.begin(&context)?;
        let invalid = product_buffers.encode(
            &mut encoder,
            &wires,
            &vec![F::ZERO; challenges],
            &vec![F::ZERO; challenges],
        )?;
        encoder.submit()?.finish()?;
        assert_eq!(
            invalid.check_status(&context).unwrap_err().to_string(),
            "permutation denominator is zero"
        );
        // Directly exercise the CPU trim equivalent with one forbidden tail
        // coefficient. The valid non-power-of-two quotient above has a zero tail.
        if !factor.is_power_of_two() {
            let mut bad = vec![F::ZERO; quotient.full_coefficients.len()];
            bad[common.quotient_degree()] = F::ONE;
            let mut encoder = workspace.begin(&context)?;
            encoder.upload(&quotient_buffers.coefficients, &bad)?;
            encoder.upload(&quotient_buffers.status, &[F::ZERO])?;
            let group = encoder.bind_with_params(
                &prepared.quotient.tail,
                &[
                    FieldBinding::ReadWrite(&quotient_buffers.status),
                    FieldBinding::Read((&quotient_buffers.coefficients).into()),
                ],
                Some(&prepared.quotient.tail_params),
                "test quotient tail",
            )?;
            encoder.dispatch_elements(
                &prepared.quotient.tail,
                &group,
                bad.len(),
                "test quotient tail",
            )?;
            encoder.submit()?.finish()?;
            assert_eq!(
                quotient.check_status(&context).unwrap_err().to_string(),
                "quotient has nonzero coefficients beyond its permitted degree"
            );
        }
    }
    Ok(())
}
