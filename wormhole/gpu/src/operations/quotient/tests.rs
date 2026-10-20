use super::*;
use crate::constraint_export::{
    ArithmeticNode, ConstraintInput, GateConstraintExpression, GateConstraintProgram,
};
use crate::ProofWorkspace;
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::plonk_common::reduce_with_powers_multi;
use plonky2::plonk::vars::EvaluationVarsBaseBatch;
use plonky2::util::reducing::ReducingFactorTarget;

#[test]
fn malformed_expression_programs_fail_closed() {
    let mut program = GateConstraintProgram::<F> {
        num_constants: 1,
        num_wires: 1,
        num_constraints: 1,
        gates: vec![GateConstraintExpression {
            gate_id: "test".into(),
            nodes: vec![ArithmeticNode::Constant(F::ZERO)],
            outputs: vec![0],
        }],
    };
    assert!(validate_program(&program).is_ok());
    program.gates[0].nodes[0] = ArithmeticNode::Add(0, 0);
    assert!(validate_program(&program).is_err());
    program.gates[0].nodes[0] = ArithmeticNode::Input(ConstraintInput::Wire(1));
    assert!(validate_program(&program).is_err());
    program.gates[0].nodes[0] = ArithmeticNode::Input(ConstraintInput::PublicInputHash(4));
    assert!(validate_program(&program).is_err());
    program.gates[0].nodes[0] = ArithmeticNode::Constant(F::ONE);
    program.gates[0].outputs[0] = 1;
    assert!(validate_program(&program).is_err());
}

/// Every gate type the recursive verifier emits (Poseidon, random access,
/// coset interpolation, reducing, exponentiation, base-sum, extension
/// arithmetic, constants, public inputs) must export to a program that agrees
/// with its CPU base-field evaluator. A recursive verifier of a tiny inner
/// proof is the smallest circuit containing all of them.
#[test]
fn exported_constraints_match_cpu_gate_evaluators_for_recursive_verifier_gates() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut inner = CircuitBuilder::<F, 2>::new(config.clone());
    let input = inner.add_virtual_target();
    let mut digest = inner.hash_n_to_hash_no_pad::<PoseidonHash>(vec![input]);
    for _ in 0..1100 {
        digest = inner.hash_n_to_hash_no_pad::<PoseidonHash>(digest.elements.to_vec());
    }
    inner.register_public_inputs(&digest.elements);
    let inner = inner.build::<PoseidonGoldilocksConfig>();
    assert!(
        inner.common.fri_params.reduction_arity_bits.len() >= 2,
        "inner proof must have FRI reduction rounds"
    );

    let mut outer = CircuitBuilder::<F, 2>::new(config);
    let proof = outer.add_virtual_proof_with_pis(&inner.common);
    let verifier = outer.add_virtual_verifier_data(inner.common.config.fri_config.cap_height);
    outer.verify_proof::<PoseidonGoldilocksConfig>(&proof, &verifier, &inner.common);
    // The verifier itself does not emit these two, so add them explicitly.
    let base = outer.add_virtual_target();
    let exponent = outer.add_virtual_target();
    outer.exp(base, exponent, 8);
    let alpha = outer.add_virtual_extension_target();
    let terms: Vec<_> = (0..40).map(|_| outer.add_virtual_target()).collect();
    ReducingFactorTarget::new(alpha).reduce_base(&terms, &mut outer);
    let outer = outer.build::<PoseidonGoldilocksConfig>();
    let gate_ids: Vec<_> = outer.common.gates.iter().map(|gate| gate.0.id()).collect();
    for required in [
        "NoopGate",
        "PoseidonGate",
        "PoseidonMdsGate",
        "RandomAccessGate",
        "CosetInterpolationGate",
        "ReducingExtensionGate",
        "ReducingGate",
        "ExponentiationGate",
        "BaseSumGate",
        "MulExtensionGate",
        "ArithmeticExtensionGate",
        "ArithmeticGate",
        "ConstantGate",
        "PublicInputGate",
    ] {
        assert!(
            gate_ids.iter().any(|id| id.starts_with(required)),
            "recursive verifier fixture lost {required}: {gate_ids:?}"
        );
    }
    check_exported_constraints(&outer.common, 16)?;

    // A program that disagrees with the evaluator must be reported, not
    // accepted: perturb one exported output of the first non-trivial gate.
    let mut program = export_gate_constraints(&outer.common)?;
    let gate = program
        .gates
        .iter_mut()
        .find(|gate| {
            gate.outputs
                .iter()
                .any(|&o| !matches!(gate.nodes[o], ArithmeticNode::Constant(_)))
        })
        .unwrap();
    gate.nodes.push(ArithmeticNode::Constant(F::ONE));
    let slot = gate
        .outputs
        .iter()
        .position(|&o| !matches!(gate.nodes[o], ArithmeticNode::Constant(_)))
        .unwrap();
    gate.outputs[slot] = gate.nodes.len() - 1;
    assert!(check_program_against_cpu(&outer.common, &program, 1)
        .unwrap_err()
        .to_string()
        .contains("disagrees with the CPU evaluator"));
    Ok(())
}

#[test]
fn zero_padding_is_not_emitted_as_horner_work() {
    let layout = QuotientLayout {
        constants: 0,
        sigmas: 1,
        wires: 2,
        zs: 3,
        partial_products: 4,
        next_zs: 5,
        x: 6,
        l0: 7,
        inverse_zero: 8,
        columns: 9,
        scalar_count: 7,
    };
    let gate = GateConstraintExpression {
        gate_id: "test".into(),
        nodes: vec![
            ArithmeticNode::Constant(F::ZERO),
            ArithmeticNode::Constant(F::ONE),
        ],
        outputs: vec![1, 0, 0, 0],
    };
    let body = gate_body(&gate, &layout, 1).unwrap();
    assert_eq!(body.matches("sum0=gf64_add").count(), 1);
    let empty = GateConstraintExpression {
        outputs: vec![0; 4],
        ..gate
    };
    assert!(gate_body(&empty, &layout, 1).is_none());
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn quotient_matches_cpu_gates_and_permutation_equations_on_arbitrary_rows() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    for challenges in [2, 3] {
        let mut config = CircuitConfig::standard_recursion_config();
        config.num_challenges = challenges;
        let mut builder = CircuitBuilder::<F, 2>::new(config);
        let values = builder.add_virtual_targets(4);
        let product = builder.mul(values[0], values[1]);
        builder.add(product, values[2]);
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(values);
        let common = builder.build::<PoseidonGoldilocksConfig>().common;
        let rows = 8;
        let plan = QuotientPlan::prepare(&context, &common, rows)?;
        let l = plan.layout();
        let mut workspace = ProofWorkspace::prepare(&context, &plan.workspace_field_counts())?;
        let row_buffer = workspace.buffer(0)?;
        let scalar_buffer = workspace.buffer(1)?;
        let weights = workspace.buffer(2)?;
        let output = workspace.buffer(3)?;
        let bits = common.quotient_degree_factor.next_power_of_two().ilog2() as usize;
        let z = ZeroPolyOnCoset::<F>::try_new(common.degree_bits(), bits)?;
        let root = F::primitive_root_of_unity(common.degree_bits() + bits);
        for seed in [7, 123] {
            let mut state: u64 = seed;
            let mut random = || {
                state = state.wrapping_mul(6364136223846793005u64).wrapping_add(1);
                F::from_noncanonical_u64(state)
            };
            let mut table = (0..l.columns * rows).map(|_| random()).collect::<Vec<_>>();
            let mut scalars = (0..l.scalar_count).map(|_| random()).collect::<Vec<_>>();
            scalars[4 + 2 * challenges] = if seed == 7 { F::ZERO } else { F::ONE };
            let mut x = F::coset_shift();
            for row in 0..rows {
                table[l.x * rows + row] = x;
                table[l.l0 * rows + row] = z.eval_l_0(row, x);
                table[l.inverse_zero * rows + row] = z.eval_inverse(row);
                x *= root;
            }
            let hash = HashOut {
                elements: scalars[..4].try_into().unwrap(),
            };
            let vars = EvaluationVarsBaseBatch::new(
                rows,
                &table[..common.num_constants * rows],
                &table[l.wires * rows..l.zs * rows],
                &hash,
            );
            let mut gate_terms = vec![F::ZERO; common.num_gate_constraints * rows];
            for (i, gate) in common.gates.iter().enumerate() {
                let selector = common.selectors_info.selector_indices[i];
                let terms = gate.0.eval_filtered_base_batch(
                    vars,
                    i,
                    selector,
                    common.selectors_info.groups[selector].clone(),
                    common.selectors_info.num_selectors(),
                    common.num_lookup_selectors,
                );
                for (sum, term) in gate_terms.iter_mut().zip(terms) {
                    *sum += term;
                }
            }
            let mut expected = vec![F::ZERO; rows * challenges];
            let value = |column: usize, row: usize| table[column * rows + row];
            for row in 0..rows {
                // Independent CPU reference: native gate evaluator, explicit
                // partial-product equalities, then CPU alpha reduction. The
                // full CPU vanishing evaluator is private; no API is added.
                let mut terms = (0..challenges)
                    .map(|i| value(l.l0, row) * (value(l.zs + i, row) - F::ONE))
                    .collect::<Vec<_>>();
                let degree = common.permutation_partial_product_degree();
                for i in 0..challenges {
                    for chunk in 0..=common.num_partial_products {
                        let indices = chunk * degree
                            ..((chunk + 1) * degree).min(common.config.num_routed_wires);
                        let numerator: F = indices
                            .clone()
                            .map(|j| {
                                value(l.wires + j, row)
                                    + scalars[4 + i] * common.k_is[j] * value(l.x, row)
                                    + scalars[4 + challenges + i]
                            })
                            .product();
                        let denominator: F = indices
                            .map(|j| {
                                value(l.wires + j, row)
                                    + scalars[4 + i] * value(l.sigmas + j, row)
                                    + scalars[4 + challenges + i]
                            })
                            .product();
                        let previous = if chunk == 0 {
                            value(l.zs + i, row)
                        } else {
                            value(
                                l.partial_products + i * common.num_partial_products + chunk - 1,
                                row,
                            )
                        };
                        let next = if chunk == common.num_partial_products {
                            value(l.next_zs + i, row)
                        } else {
                            value(
                                l.partial_products + i * common.num_partial_products + chunk,
                                row,
                            )
                        };
                        terms.push(previous * numerator - next * denominator);
                    }
                }
                terms.extend((0..common.num_gate_constraints).map(|i| gate_terms[i * rows + row]));
                for (i, result) in reduce_with_powers_multi(&terms, &scalars[4 + 2 * challenges..])
                    .into_iter()
                    .enumerate()
                {
                    expected[i * rows + row] = result * value(l.inverse_zero, row);
                }
            }
            let mut encoder = workspace.begin(&context)?;
            encoder.upload(&row_buffer, &table)?;
            encoder.upload(&scalar_buffer, &scalars)?;
            plan.encode(&mut encoder, &row_buffer, &scalar_buffer, &weights, &output)?;
            encoder.submit()?.finish()?;
            assert_eq!(
                context.readback(&output)?,
                expected,
                "quotient {challenges} challenges, seed {seed}"
            );
        }
    }
    Ok(())
}
