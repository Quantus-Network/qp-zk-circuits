use super::*;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::fri::FriParamsObserve;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::Challenger;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::plonk_common::reduce_with_powers_multi;
use plonky2::plonk::prover::prove_with_partition_witness;
use plonky2::plonk::vars::EvaluationVarsBaseBatch;
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
fn resident_products_and_quotient_match_cpu_prover_across_domains() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    for (challenges, factor, rate) in [(2, 8, 3), (3, 7, 4)] {
        let mut config = CircuitConfig::standard_recursion_config();
        config.num_challenges = challenges;
        config.max_quotient_degree_factor = factor;
        config.fri_config.rate_bits = rate;
        // A tiny proof is an independent CPU oracle, not an arity benchmark.
        config.fri_config.proof_of_work_bits = 0;
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
        let mut workspace = ProofWorkspace::prepare(&context, &counts)?;
        let wire_buffers = prepared.wire_buffers(&workspace, 0)?;
        let product_buffers = prepared.permutation_buffers(&workspace, pfirst)?;
        let quotient_buffers = prepared.quotient_buffers(&workspace, qfirst)?;
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
