//! Gadget-call traces for the formal constraint exporter (`qp-plonky2/constraint-exporter`,
//! PLAN.md Step 8c).
//!
//! [`TracingBuilder`] implements [`GadgetBuilder`] over a real `CircuitBuilder` and records,
//! for every gadget call, the targets involved and the gate rows / copy constraints the call
//! actually emitted (read off `formal_export_view` before and after). [`Trace`] bundles the
//! calls with the builder's final constraint system in a plain JSON shape, so the exporter,
//! which cannot link against this crate, can regenerate the wrapper's Lean decode theorem
//! from the checked-in trace alone.

use alloc::{format, string::String, vec::Vec};
use plonky2::{
    field::types::PrimeField64,
    hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use serde::{Deserialize, Serialize};

use crate::{
    circuit::{D, F},
    gadget_builder::GadgetBuilder,
};

/// `w{row}:{column}` for wires, `v{index}` for virtual targets.
pub fn encode_target(t: Target) -> String {
    match t {
        Target::Wire(w) => format!("w{}:{}", w.row, w.column),
        Target::VirtualTarget { index } => format!("v{index}"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRow {
    /// `Gate::id()` of the placed gate.
    pub gate: String,
    /// The row's gate constants, canonical decimal.
    pub constants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCall {
    /// `select`, `not`, `and`, `or`, `add`, `sub`, `mul`, `is_equal`, `range_check`,
    /// `connect`, `assert_bool` (`add_virtual_bool_target_safe`), `poseidon2_hash`.
    pub kind: String,
    pub args: Vec<String>,
    pub outs: Vec<String>,
    /// Non-constant virtual targets the call allocated (`is_equal`'s inverse).
    pub fresh: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<usize>,
    /// Half-open range of gate rows the call added.
    pub rows: [usize; 2],
    /// Half-open range of copy constraints the call added.
    pub copies: [usize; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub circuit: String,
    pub num_routed_wires: usize,
    pub rows: Vec<TraceRow>,
    pub copies: Vec<[String; 2]>,
    /// Constant targets and their values, sorted by target.
    pub constants: Vec<(String, String)>,
    pub public_inputs: Vec<String>,
    pub num_virtual_targets: usize,
    /// Targets of interest by role, so the Lean statement can refer to them.
    pub named: Vec<(String, Vec<String>)>,
    pub calls: Vec<TraceCall>,
}

impl Trace {
    /// One JSON object per line for rows, copies, constants and calls, so diffs stay local.
    pub fn to_json(&self) -> String {
        fn list<T: Serialize>(items: &[T]) -> String {
            let lines: Vec<String> = items
                .iter()
                .map(|i| format!("    {}", serde_json::to_string(i).expect("serializable")))
                .collect();
            if lines.is_empty() {
                "[]".into()
            } else {
                format!("[\n{}\n  ]", lines.join(",\n"))
            }
        }
        format!(
            "{{\n  \"circuit\": {},\n  \"num_routed_wires\": {},\n  \"num_virtual_targets\": {},\n  \
             \"rows\": {},\n  \"copies\": {},\n  \"constants\": {},\n  \"public_inputs\": {},\n  \
             \"named\": {},\n  \"calls\": {}\n}}\n",
            serde_json::to_string(&self.circuit).expect("serializable"),
            self.num_routed_wires,
            self.num_virtual_targets,
            list(&self.rows),
            list(&self.copies),
            list(&self.constants),
            list(&self.public_inputs),
            list(&self.named),
            list(&self.calls),
        )
    }

    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// A `CircuitBuilder` that records the gadget calls made through [`GadgetBuilder`].
pub struct TracingBuilder {
    pub inner: CircuitBuilder<F, D>,
    pub calls: Vec<TraceCall>,
    num_routed_wires: usize,
}

impl TracingBuilder {
    pub fn new(config: CircuitConfig) -> Self {
        TracingBuilder {
            num_routed_wires: config.num_routed_wires,
            inner: CircuitBuilder::new(config),
            calls: Vec::new(),
        }
    }

    fn counts(&self) -> (usize, usize, usize) {
        let v = self.inner.formal_export_view();
        (
            v.gate_instances.len(),
            v.copy_constraints.len(),
            v.num_virtual_targets,
        )
    }

    fn record<T>(
        &mut self,
        kind: &str,
        args: &[Target],
        bits: Option<usize>,
        f: impl FnOnce(&mut CircuitBuilder<F, D>) -> T,
        outs: impl FnOnce(&T) -> Vec<Target>,
    ) -> T {
        let (rows0, copies0, virt0) = self.counts();
        let r = f(&mut self.inner);
        let (rows1, copies1, virt1) = self.counts();
        let view = self.inner.formal_export_view();
        let fresh = (virt0..virt1)
            .map(|index| Target::VirtualTarget { index })
            .filter(|t| !view.constant_targets.contains_key(t))
            .map(encode_target)
            .collect();
        self.calls.push(TraceCall {
            kind: kind.into(),
            args: args.iter().copied().map(encode_target).collect(),
            outs: outs(&r).into_iter().map(encode_target).collect(),
            fresh,
            bits,
            rows: [rows0, rows1],
            copies: [copies0, copies1],
        });
        r
    }

    /// Snapshot the constraint system and the recorded calls.
    pub fn trace(&self, circuit: &str, named: Vec<(String, Vec<Target>)>) -> Trace {
        let view = self.inner.formal_export_view();
        let pending: usize = view.lookups.iter().map(Vec::len).sum();
        assert_eq!(pending, 0, "lookups are not modeled by the exporter");
        let mut constants: Vec<(String, String)> = view
            .constant_targets
            .iter()
            .map(|(t, v)| (encode_target(*t), format!("{}", v.to_canonical_u64())))
            .collect();
        constants.sort();
        Trace {
            circuit: circuit.into(),
            num_routed_wires: self.num_routed_wires,
            rows: view
                .gate_instances
                .iter()
                .map(|gi| TraceRow {
                    gate: gi.gate_ref.0.id(),
                    constants: gi
                        .constants
                        .iter()
                        .map(|c| format!("{}", c.to_canonical_u64()))
                        .collect(),
                })
                .collect(),
            copies: view
                .copy_constraints
                .iter()
                .map(|c| [encode_target(c.pair.0), encode_target(c.pair.1)])
                .collect(),
            constants,
            public_inputs: view
                .public_inputs
                .iter()
                .copied()
                .map(encode_target)
                .collect(),
            num_virtual_targets: view.num_virtual_targets,
            named: named
                .into_iter()
                .map(|(n, ts)| (n, ts.into_iter().map(encode_target).collect()))
                .collect(),
            calls: self.calls.clone(),
        }
    }
}

impl GadgetBuilder<F, D> for TracingBuilder {
    fn one(&mut self) -> Target {
        self.inner.one()
    }
    fn zero(&mut self) -> Target {
        self.inner.zero()
    }
    fn constant(&mut self, c: F) -> Target {
        self.inner.constant(c)
    }
    fn _false(&mut self) -> BoolTarget {
        self.inner._false()
    }
    fn add_virtual_bool_target_safe(&mut self) -> BoolTarget {
        self.record(
            "assert_bool",
            &[],
            None,
            |b| b.add_virtual_bool_target_safe(),
            |r| alloc::vec![r.target],
        )
    }
    fn not(&mut self, b: BoolTarget) -> BoolTarget {
        self.record(
            "not",
            &[b.target],
            None,
            |bd| bd.not(b),
            |r| alloc::vec![r.target],
        )
    }
    fn and(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget {
        self.record(
            "and",
            &[b1.target, b2.target],
            None,
            |bd| bd.and(b1, b2),
            |r| alloc::vec![r.target],
        )
    }
    fn or(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget {
        self.record(
            "or",
            &[b1.target, b2.target],
            None,
            |bd| bd.or(b1, b2),
            |r| alloc::vec![r.target],
        )
    }
    fn select(&mut self, b: BoolTarget, x: Target, y: Target) -> Target {
        self.record(
            "select",
            &[b.target, x, y],
            None,
            |bd| bd.select(b, x, y),
            |&out| alloc::vec![out],
        )
    }
    fn is_equal(&mut self, x: Target, y: Target) -> BoolTarget {
        self.record(
            "is_equal",
            &[x, y],
            None,
            |bd| bd.is_equal(x, y),
            |r| alloc::vec![r.target],
        )
    }
    fn add(&mut self, x: Target, y: Target) -> Target {
        self.record(
            "add",
            &[x, y],
            None,
            |bd| bd.add(x, y),
            |&out| alloc::vec![out],
        )
    }
    fn sub(&mut self, x: Target, y: Target) -> Target {
        self.record(
            "sub",
            &[x, y],
            None,
            |bd| bd.sub(x, y),
            |&out| alloc::vec![out],
        )
    }
    fn mul(&mut self, x: Target, y: Target) -> Target {
        self.record(
            "mul",
            &[x, y],
            None,
            |bd| bd.mul(x, y),
            |&out| alloc::vec![out],
        )
    }
    fn connect(&mut self, x: Target, y: Target) {
        self.record(
            "connect",
            &[x, y],
            None,
            |bd| bd.connect(x, y),
            |_| Vec::new(),
        );
    }
    fn range_check(&mut self, x: Target, n_log: usize) {
        self.record(
            "range_check",
            &[x],
            Some(n_log),
            |bd| bd.range_check(x, n_log),
            |_| Vec::new(),
        );
    }
    fn register_public_inputs(&mut self, targets: &[Target]) {
        self.inner.register_public_inputs(targets)
    }
    fn poseidon2_hash_no_pad(&mut self, inputs: Vec<Target>) -> HashOutTarget {
        let args = inputs.clone();
        self.record(
            "poseidon2_hash",
            &args,
            None,
            |bd| bd.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inputs),
            |r| r.elements.to_vec(),
        )
    }
}
