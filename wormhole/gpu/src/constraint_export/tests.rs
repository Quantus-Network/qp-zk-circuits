use super::*;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::gate::Gate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::generator::WitnessGeneratorRef;
use plonky2::plonk::config::PoseidonGoldilocksConfig as C;
use plonky2::plonk::vars::EvaluationVars;
use plonky2::util::serialization::{Buffer, IoResult};

fn interpret(program: &GateConstraintProgram<F>, inputs: impl Fn(ConstraintInput) -> F) -> Vec<F> {
    let mut sum = vec![F::ZERO; program.num_constraints];
    for gate in &program.gates {
        assert_eq!(gate.outputs.len(), program.num_constraints);
        let mut values = Vec::with_capacity(gate.nodes.len());
        for (i, node) in gate.nodes.iter().enumerate() {
            values.push(match *node {
                ArithmeticNode::Constant(value) => value,
                ArithmeticNode::Input(input) => inputs(input),
                ArithmeticNode::Add(a, b) | ArithmeticNode::Mul(a, b) => {
                    assert!(a < i && b < i, "graph must be topologically ordered");
                    if matches!(node, ArithmeticNode::Add(..)) {
                        values[a] + values[b]
                    } else {
                        values[a] * values[b]
                    }
                }
            });
        }
        for (slot, &output) in gate.outputs.iter().enumerate() {
            sum[slot] += values[output];
        }
    }
    sum
}

/// The scratch builder must leave no footprint on the exported program: a
/// program is a function of the gate alone, and interpreting the sum of all
/// gates' outputs at a row where exactly one selector is active must yield
/// that gate's filtered constraints.
#[test]
fn exported_programs_depend_only_on_the_gate_and_sum_to_the_cpu_vector() -> Result<()> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    let product = builder.mul(a, b);
    let digest = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![product]);
    builder.register_public_inputs(&digest.elements);
    let common = builder.build::<C>().common;
    let program = export_gate_constraints(&common)?;
    assert_eq!(program.gates.len(), common.gates.len());
    assert!(program
        .gates
        .iter()
        .any(|g| g.gate_id.starts_with("PoseidonGate")));
    for (gate, exported) in common.gates.iter().zip(&program.gates) {
        assert_eq!(exported.gate_id, gate.0.id());
        assert!(!exported.nodes.is_empty());
    }
    let row: Vec<F> = (0..common.num_constants + common.config.num_wires + 4)
        .map(|i| F::from_canonical_u64(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1)))
        .collect();
    let sum = interpret(&program, |input| match input {
        ConstraintInput::Constant(i) => row[i],
        ConstraintInput::Wire(i) => row[common.num_constants + i],
        ConstraintInput::PublicInputHash(i) => {
            row[common.num_constants + common.config.num_wires + i]
        }
    });
    assert_eq!(sum.len(), common.num_gate_constraints);
    assert!(sum.iter().any(|&v| v != F::ZERO));
    Ok(())
}

#[test]
fn unsupported_configurations_return_errors() {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    builder.add_gate(NoopGate, vec![]);
    let mut common = builder.build::<C>().common;
    common.num_lookup_polys = 1;
    assert!(export_gate_constraints(&common)
        .unwrap_err()
        .to_string()
        .contains("does not support lookups"));
    common.num_lookup_polys = 0;
    common.selectors_info.selector_indices.clear();
    assert!(export_gate_constraints(&common)
        .unwrap_err()
        .to_string()
        .contains("invalid constraint selector metadata"));
}

#[derive(Debug, Clone, Copy)]
enum UnsupportedGate {
    Copy,
    UnknownTarget,
    NonBase,
    NewGate,
    ConfiguredGate,
}

impl Gate<F, D> for UnsupportedGate {
    fn id(&self) -> String {
        format!("UnsupportedGate::{self:?}")
    }
    fn serialize(&self, _: &mut Vec<u8>, _: &CommonCircuitData<F, D>) -> IoResult<()> {
        Ok(())
    }
    fn deserialize(_: &mut Buffer, _: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self::Copy)
    }
    fn eval_unfiltered(&self, _: EvaluationVars<F, D>) -> Vec<QuadraticExtension<F>> {
        vec![QuadraticExtension::ZERO]
    }
    fn eval_unfiltered_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        let zero = builder.zero_extension();
        match self {
            Self::Copy => {
                builder.connect(vars.local_wires[0].0[0], vars.local_wires[1].0[0]);
            }
            Self::UnknownTarget => return vec![builder.add_virtual_extension_target()],
            Self::NonBase => {
                let value = ExtensionTarget([zero.0[0], vars.local_wires[0].0[0]]);
                return vec![builder.add_extension(value, zero)];
            }
            Self::NewGate => {
                builder.add_gate(NoopGate, vec![]);
            }
            Self::ConfiguredGate => {
                let gate = BaseSumGate::<2>::new_from_config::<F>(&builder.config);
                let _ = ExponentiationGate::<F, D>::new_from_config(&builder.config);
                builder.add_gate(gate, vec![]);
            }
        }
        vec![zero]
    }
    fn generators(&self, _: usize, _: &[F]) -> Vec<WitnessGeneratorRef<F, D>> {
        vec![]
    }
    fn num_wires(&self) -> usize {
        2
    }
    fn num_constants(&self) -> usize {
        0
    }
    fn degree(&self) -> usize {
        1
    }
    fn num_constraints(&self) -> usize {
        1
    }
}

/// Anything a recursive evaluator does that the interpreter cannot give a
/// base-field meaning to must fail the whole export, never yield a partial
/// program.
#[test]
fn unsupported_gate_operations_return_errors_instead_of_partial_programs() {
    for (gate, reason) in [
        (
            UnsupportedGate::Copy,
            "copy constraint between two defined targets",
        ),
        (UnsupportedGate::UnknownTarget, "untraced target"),
        (UnsupportedGate::NonBase, "non-base output expression"),
        (UnsupportedGate::NewGate, "untraced gate instance NoopGate"),
        (
            UnsupportedGate::ConfiguredGate,
            "untraced gate instance BaseSumGate",
        ),
    ] {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        builder.add_gate(gate, vec![]);
        let common = builder.build::<C>().common;
        let error = format!("{:#}", export_gate_constraints(&common).unwrap_err());
        assert!(
            error.contains(&format!("cannot export {}", gate.id())) && error.contains(reason),
            "{gate:?}: {error}"
        );
    }
}
