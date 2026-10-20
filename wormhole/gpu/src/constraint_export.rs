//! Backend-neutral arithmetic expressions for selector-filtered gate constraints.
//!
//! Each gate's recursive evaluator (`Gate::eval_filtered_circuit`) is run,
//! unmodified, against a scratch `CircuitBuilder` whose inputs are the gate's
//! constant, wire and public-input-hash columns. The gates and copy constraints
//! that evaluator places are then read back through the dependency's
//! `formal-export` view and interpreted symbolically. Nothing in the dependency
//! is hooked: recursive evaluators only materialise arithmetic as
//! `ArithmeticExtensionGate`, `MulExtensionGate`, `ReducingGate`,
//! `ReducingExtensionGate` and `PoseidonMdsGate` rows wired together by copy
//! constraints; any other row fails the export.
//!
//! Export supports Goldilocks with extension degree two and no lookups.
use anyhow::{bail, ensure, Result};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::Poseidon;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::plonk::vars::EvaluationTargets;
use std::collections::HashMap;

#[cfg(test)]
mod tests;

/// One base-field input to a gate constraint expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintInput {
    /// A constant/selector column, before removing the selector prefix.
    Constant(usize),
    /// A wire column in the circuit's wire order.
    Wire(usize),
    /// An element of the four-element public-input hash.
    PublicInputHash(usize),
}

/// An arithmetic node. Child indices refer to earlier nodes in the same graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticNode<F: Field> {
    Constant(F),
    Input(ConstraintInput),
    Add(usize, usize),
    Mul(usize, usize),
}

/// The ordered, selector-filtered constraints for one gate type.
#[derive(Debug, Clone)]
pub struct GateConstraintExpression<F: Field> {
    pub gate_id: String,
    /// Nodes in topological order. Only nodes needed by the outputs are retained.
    pub nodes: Vec<ArithmeticNode<F>>,
    /// One node per common gate-constraint slot, including zero padding.
    pub outputs: Vec<usize>,
}

/// Circuit gate constraints without backend code or device-specific layouts.
#[derive(Debug, Clone)]
pub struct GateConstraintProgram<F: Field> {
    pub num_constants: usize,
    pub num_wires: usize,
    pub num_constraints: usize,
    /// Same gate order as `CommonCircuitData::gates`. Sum corresponding outputs
    /// across gates to obtain the CPU gate-constraint vector.
    pub gates: Vec<GateConstraintExpression<F>>,
}

const D: usize = 2;
const SPONGE_WIDTH: usize = 12;

/// Export gate constraints from their existing recursive definitions.
///
/// Custom gate evaluators must obey the same contracts as normal recursive
/// evaluation, including valid wire and constant indices. Panics in arbitrary
/// custom gate code are not caught.
pub fn export_gate_constraints(
    common: &CommonCircuitData<F, D>,
) -> Result<GateConstraintProgram<F>> {
    ensure!(
        common.num_lookup_selectors == 0 && common.num_lookup_polys == 0 && common.luts.is_empty(),
        "constraint export does not support lookups"
    );
    let selectors = &common.selectors_info;
    ensure!(
        selectors.selector_indices.len() == common.gates.len()
            && selectors.num_selectors() <= common.num_constants
            && selectors
                .selector_indices
                .iter()
                .enumerate()
                .all(|(gate_index, &index)| {
                    index < selectors.groups.len() && selectors.groups[index].contains(&gate_index)
                }),
        "invalid constraint selector metadata"
    );
    let mut config = CircuitConfig::standard_recursion_config();
    config.use_base_arithmetic_gate = false;
    let mut gates = Vec::with_capacity(common.gates.len());
    for (gate_index, gate) in common.gates.iter().enumerate() {
        let gate_id = gate.0.id();
        ensure!(
            gate.0.num_constraints() <= common.num_gate_constraints,
            "cannot export {gate_id}: constraint count exceeds common metadata"
        );
        ensure!(
            gate.0.num_wires() <= common.config.num_wires
                && gate.0.num_constants() <= common.num_constants - selectors.num_selectors(),
            "cannot export {gate_id}: gate inputs exceed common metadata"
        );
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let mut inputs = Vec::new();
        let mut input = |kind| {
            let target = builder.add_virtual_target();
            inputs.push((target, kind));
            target
        };
        let constants: Vec<_> = (0..common.num_constants)
            .map(|i| input(ConstraintInput::Constant(i)))
            .collect();
        let wires: Vec<_> = (0..common.config.num_wires)
            .map(|i| input(ConstraintInput::Wire(i)))
            .collect();
        let hash = HashOutTarget {
            elements: core::array::from_fn(|i| input(ConstraintInput::PublicInputHash(i))),
        };
        let constants: Vec<_> = constants
            .iter()
            .map(|&t| builder.convert_to_ext(t))
            .collect();
        let wires: Vec<_> = wires.iter().map(|&t| builder.convert_to_ext(t)).collect();
        let vars = EvaluationTargets {
            local_constants: &constants,
            local_wires: &wires,
            public_inputs_hash: &hash,
        };
        let mut constraints = vec![builder.zero_extension(); common.num_gate_constraints];
        let selector = selectors.selector_indices[gate_index];
        gate.0.eval_filtered_circuit(
            &mut builder,
            vars,
            gate_index,
            selector,
            selectors.groups[selector].clone(),
            selectors.num_selectors(),
            0,
            &mut constraints,
        );
        let (nodes, outputs) = Interpreter::run(&builder, &inputs, &constraints)
            .map_err(|error| error.context(format!("cannot export {gate_id}")))?;
        gates.push(GateConstraintExpression {
            gate_id,
            nodes,
            outputs,
        });
    }
    Ok(GateConstraintProgram {
        num_constants: common.num_constants,
        num_wires: common.config.num_wires,
        num_constraints: common.num_gate_constraints,
        gates,
    })
}

fn target_key(target: Target) -> (usize, usize, usize) {
    match target {
        Target::Wire(wire) => (0, wire.row, wire.column),
        Target::VirtualTarget { index } => (1, index, 0),
    }
}

/// A gate row a recursive evaluator may place, with the shape read from the
/// gate's wire count so no gate-private layout helpers are needed.
#[derive(Clone, Copy, Debug)]
enum Row {
    Arithmetic { c0: F, c1: F, num_ops: usize },
    Mul { c0: F, num_ops: usize },
    Reducing { num_coeffs: usize, extension: bool },
    Mds,
}

impl Row {
    fn classify(instance: &plonky2::gates::gate::GateInstance<F, D>) -> Result<Self> {
        let gate = &instance.gate_ref.0;
        let id = gate.id();
        let wires = gate.num_wires();
        let kind = if id.starts_with("ArithmeticExtensionGate") {
            let [c0, c1] = instance.constants[..] else {
                bail!("unexpected constants on {id}");
            };
            Self::Arithmetic {
                c0,
                c1,
                num_ops: wires / (4 * D),
            }
        } else if id.starts_with("MulExtensionGate") {
            let [c0] = instance.constants[..] else {
                bail!("unexpected constants on {id}");
            };
            Self::Mul {
                c0,
                num_ops: wires / (3 * D),
            }
        } else if id.starts_with("ReducingExtensionGate") {
            Self::Reducing {
                num_coeffs: (wires - 2 * D) / (2 * D),
                extension: true,
            }
        } else if id.starts_with("ReducingGate") {
            Self::Reducing {
                num_coeffs: (wires - 2 * D) / (D + 1),
                extension: false,
            }
        } else if id.starts_with("PoseidonMdsGate") {
            Self::Mds
        } else {
            bail!("untraced gate instance {id}");
        };
        ensure!(
            matches!(kind, Self::Arithmetic { .. } | Self::Mul { .. })
                || instance.constants.is_empty(),
            "unexpected constants on {id}"
        );
        ensure!(
            wires
                == match kind {
                    Self::Arithmetic { num_ops, .. } => num_ops * 4 * D,
                    Self::Mul { num_ops, .. } => num_ops * 3 * D,
                    Self::Reducing {
                        num_coeffs,
                        extension: true,
                    } => 2 * D + 2 * D * num_coeffs,
                    Self::Reducing {
                        num_coeffs,
                        extension: false,
                    } => 2 * D + num_coeffs * (D + 1),
                    Self::Mds => 2 * D * SPONGE_WIDTH,
                },
            "unexpected wire layout on {id}"
        );
        Ok(kind)
    }

    fn slots(self) -> usize {
        match self {
            Self::Arithmetic { num_ops, .. } | Self::Mul { num_ops, .. } => num_ops,
            Self::Reducing { .. } | Self::Mds => 1,
        }
    }
}

/// Symbolic evaluation of a scratch builder's rows: targets are resolved
/// through copy constraints to a node, and each placed row defines its output
/// wires from its input wires.
struct Interpreter {
    nodes: Vec<ArithmeticNode<F>>,
    parent: HashMap<Target, Target>,
    values: HashMap<Target, usize>,
}

impl Interpreter {
    fn run(
        builder: &CircuitBuilder<F, D>,
        inputs: &[(Target, ConstraintInput)],
        constraints: &[ExtensionTarget<D>],
    ) -> Result<(Vec<ArithmeticNode<F>>, Vec<usize>)> {
        let view = builder.formal_export_view();
        ensure!(
            view.lookups.iter().all(Vec::is_empty) && view.public_inputs.is_empty(),
            "untraced builder state"
        );
        let mut this = Self {
            nodes: Vec::new(),
            parent: HashMap::new(),
            values: HashMap::new(),
        };
        for &(target, kind) in inputs {
            let node = this.push(ArithmeticNode::Input(kind));
            this.values.insert(target, node);
        }
        for constraint in view.copy_constraints {
            this.union(constraint.pair.0, constraint.pair.1)?;
        }
        // The builder's map is a hash map; give the graph a deterministic order.
        let mut constants: Vec<_> = view.constant_targets.iter().collect();
        constants.sort_by_key(|(target, value)| (value.to_canonical_u64(), target_key(**target)));
        for (&target, &value) in constants {
            let node = this.push(ArithmeticNode::Constant(value));
            this.define(target, node)?;
        }
        let rows = view
            .gate_instances
            .iter()
            .map(Row::classify)
            .collect::<Result<Vec<_>>>()?;
        // Slot allocation reuses earlier rows, so a slot's inputs may come from
        // a later row; iterate to a fixpoint instead of assuming row order.
        let mut pending: Vec<(usize, usize)> = rows
            .iter()
            .enumerate()
            .flat_map(|(row, kind)| (0..kind.slots()).map(move |slot| (row, slot)))
            .collect();
        loop {
            let before = pending.len();
            let mut remaining = Vec::with_capacity(before);
            for (row, slot) in pending {
                if !this.slot(row, slot, &rows[row])? {
                    remaining.push((row, slot));
                }
            }
            pending = remaining;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        let outputs = constraints
            .iter()
            .map(|target| this.base(*target))
            .collect::<Result<Vec<_>>>()?;
        Ok(this.compact(outputs))
    }

    fn push(&mut self, node: ArithmeticNode<F>) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn find(&mut self, target: Target) -> Target {
        let mut root = target;
        while let Some(&parent) = self.parent.get(&root) {
            root = parent;
        }
        let mut current = target;
        while let Some(&parent) = self.parent.get(&current) {
            self.parent.insert(current, root);
            current = parent;
        }
        root
    }

    fn union(&mut self, a: Target, b: Target) -> Result<()> {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return Ok(());
        }
        let value = match (self.values.remove(&a), self.values.remove(&b)) {
            (Some(x), Some(y)) => {
                ensure!(x == y, "copy constraint between two defined targets");
                Some(x)
            }
            (x, y) => x.or(y),
        };
        self.parent.insert(b, a);
        if let Some(value) = value {
            self.values.insert(a, value);
        }
        Ok(())
    }

    fn define(&mut self, target: Target, node: usize) -> Result<()> {
        let root = self.find(target);
        ensure!(
            self.values.insert(root, node).is_none(),
            "target defined twice"
        );
        Ok(())
    }

    fn get(&mut self, target: Target) -> Option<usize> {
        let root = self.find(target);
        self.values.get(&root).copied()
    }

    fn resolve(&mut self, target: Target) -> Result<usize> {
        let root = self.find(target);
        self.values
            .get(&root)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("untraced target"))
    }

    fn value(&self, node: usize) -> Option<F> {
        match self.nodes[node] {
            ArithmeticNode::Constant(value) => Some(value),
            _ => None,
        }
    }

    fn binary(&mut self, a: usize, b: usize, multiply: bool) -> usize {
        let (x, y) = (self.value(a), self.value(b));
        if let (Some(x), Some(y)) = (x, y) {
            return self.push(ArithmeticNode::Constant(if multiply {
                x * y
            } else {
                x + y
            }));
        }
        if multiply && (x == Some(F::ZERO) || y == Some(F::ZERO)) {
            return self.push(ArithmeticNode::Constant(F::ZERO));
        }
        let identity = if multiply { F::ONE } else { F::ZERO };
        if x == Some(identity) {
            return b;
        }
        if y == Some(identity) {
            return a;
        }
        self.push(if multiply {
            ArithmeticNode::Mul(a, b)
        } else {
            ArithmeticNode::Add(a, b)
        })
    }

    fn add(&mut self, a: usize, b: usize) -> usize {
        self.binary(a, b, false)
    }

    fn mul(&mut self, a: usize, b: usize) -> usize {
        self.binary(a, b, true)
    }

    fn constant(&mut self, value: F) -> usize {
        self.push(ArithmeticNode::Constant(value))
    }

    /// Quadratic-extension product over the base-field node graph.
    fn ext_mul(&mut self, a: [usize; D], b: [usize; D]) -> [usize; D] {
        let w = self.constant(<F as Extendable<D>>::W);
        let a0b0 = self.mul(a[0], b[0]);
        let a1b1 = self.mul(a[1], b[1]);
        let wa1b1 = self.mul(w, a1b1);
        let a0b1 = self.mul(a[0], b[1]);
        let a1b0 = self.mul(a[1], b[0]);
        [self.add(a0b0, wa1b1), self.add(a0b1, a1b0)]
    }

    fn ext_add(&mut self, a: [usize; D], b: [usize; D]) -> [usize; D] {
        [self.add(a[0], b[0]), self.add(a[1], b[1])]
    }

    fn ext_scale(&mut self, scalar: F, a: [usize; D]) -> [usize; D] {
        let scalar = self.constant(scalar);
        [self.mul(scalar, a[0]), self.mul(scalar, a[1])]
    }

    /// The extension element held in a row's wire range, if every wire is
    /// connected to something already defined.
    fn ext_input(&mut self, row: usize, first: usize) -> Option<[usize; D]> {
        let components: [Option<usize>; D] =
            core::array::from_fn(|i| self.get(Target::wire(row, first + i)));
        Some([components[0]?, components[1]?])
    }

    fn ext_define(&mut self, row: usize, first: usize, value: [usize; D]) -> Result<()> {
        for (i, node) in value.into_iter().enumerate() {
            self.define(Target::wire(row, first + i), node)?;
        }
        Ok(())
    }

    /// One slot of a gate row. Returns whether the slot was evaluated; a slot
    /// whose inputs are not all defined yet is left for a later pass, and one
    /// whose inputs are never connected is unused.
    fn slot(&mut self, row: usize, slot: usize, kind: &Row) -> Result<bool> {
        match *kind {
            Row::Arithmetic { c0, c1, .. } => {
                let base = 4 * D * slot;
                let (Some(m0), Some(m1), Some(addend)) = (
                    self.ext_input(row, base),
                    self.ext_input(row, base + D),
                    self.ext_input(row, base + 2 * D),
                ) else {
                    return Ok(false);
                };
                let product = self.ext_mul(m0, m1);
                let product = self.ext_scale(c0, product);
                let addend = self.ext_scale(c1, addend);
                let output = self.ext_add(product, addend);
                self.ext_define(row, base + 3 * D, output)?;
            }
            Row::Mul { c0, .. } => {
                let base = 3 * D * slot;
                let (Some(m0), Some(m1)) =
                    (self.ext_input(row, base), self.ext_input(row, base + D))
                else {
                    return Ok(false);
                };
                let product = self.ext_mul(m0, m1);
                let output = self.ext_scale(c0, product);
                self.ext_define(row, base + 2 * D, output)?;
            }
            Row::Reducing {
                num_coeffs,
                extension,
            } => {
                // Wires: output, alpha, old_acc, then coefficients (base or
                // extension), then the intermediate accumulators; the last
                // accumulator is the output.
                let (Some(alpha), Some(old_acc)) =
                    (self.ext_input(row, D), self.ext_input(row, 2 * D))
                else {
                    return Ok(false);
                };
                let coefficient_width = if extension { D } else { 1 };
                let mut coefficients = Vec::with_capacity(num_coeffs);
                for i in 0..num_coeffs {
                    let first = 3 * D + i * coefficient_width;
                    let coefficient = if extension {
                        self.ext_input(row, first)
                    } else {
                        self.get(Target::wire(row, first))
                            .map(|node| [node, self.constant(F::ZERO)])
                    };
                    let Some(coefficient) = coefficient else {
                        return Ok(false);
                    };
                    coefficients.push(coefficient);
                }
                let accumulators = 3 * D + num_coeffs * coefficient_width;
                let mut acc = old_acc;
                for (i, coefficient) in coefficients.into_iter().enumerate() {
                    acc = self.ext_mul(acc, alpha);
                    acc = self.ext_add(acc, coefficient);
                    let first = if i + 1 == num_coeffs {
                        0
                    } else {
                        accumulators + D * i
                    };
                    self.ext_define(row, first, acc)?;
                }
            }
            Row::Mds => {
                let mut state = Vec::with_capacity(SPONGE_WIDTH);
                for i in 0..SPONGE_WIDTH {
                    let Some(input) = self.ext_input(row, i * D) else {
                        return Ok(false);
                    };
                    state.push(input);
                }
                for r in 0..SPONGE_WIDTH {
                    let mut acc = [self.constant(F::ZERO); D];
                    for i in 0..SPONGE_WIDTH {
                        let coefficient =
                            F::from_canonical_u64(<F as Poseidon>::MDS_MATRIX_CIRC[i]);
                        let term = self.ext_scale(coefficient, state[(i + r) % SPONGE_WIDTH]);
                        acc = self.ext_add(acc, term);
                    }
                    let coefficient = F::from_canonical_u64(<F as Poseidon>::MDS_MATRIX_DIAG[r]);
                    let term = self.ext_scale(coefficient, state[r]);
                    acc = self.ext_add(acc, term);
                    self.ext_define(row, (SPONGE_WIDTH + r) * D, acc)?;
                }
            }
        }
        Ok(true)
    }

    /// The base-field node of an extension target whose other component is a
    /// known zero.
    fn base(&mut self, target: ExtensionTarget<D>) -> Result<usize> {
        for &component in &target.0[1..] {
            let node = self.resolve(component)?;
            ensure!(
                self.value(node) == Some(F::ZERO),
                "non-base output expression"
            );
        }
        self.resolve(target.0[0])
    }

    fn compact(self, outputs: Vec<usize>) -> (Vec<ArithmeticNode<F>>, Vec<usize>) {
        let mut used = vec![false; self.nodes.len()];
        for &output in &outputs {
            used[output] = true;
        }
        for i in (0..self.nodes.len()).rev() {
            if used[i] {
                if let ArithmeticNode::Add(a, b) | ArithmeticNode::Mul(a, b) = self.nodes[i] {
                    used[a] = true;
                    used[b] = true;
                }
            }
        }
        let mut remap = vec![0; self.nodes.len()];
        let mut nodes = Vec::new();
        for (i, node) in self.nodes.into_iter().enumerate() {
            if used[i] {
                remap[i] = nodes.len();
                nodes.push(match node {
                    ArithmeticNode::Add(a, b) => ArithmeticNode::Add(remap[a], remap[b]),
                    ArithmeticNode::Mul(a, b) => ArithmeticNode::Mul(remap[a], remap[b]),
                    node => node,
                });
            }
        }
        (nodes, outputs.into_iter().map(|i| remap[i]).collect())
    }
}
