//! Gadget-call traces for the formal constraint exporter (`qp-plonky2/constraint-exporter`,
//! PLAN.md Steps 8c and 19).
//!
//! [`TracingBuilder`] implements [`GadgetBuilder`] over a real `CircuitBuilder` and records,
//! for every gadget call, the targets involved and the gate rows / copy constraints the call
//! actually emitted (read off `formal_export_view` before and after). [`Trace`] bundles the
//! calls with the builder's constraint system in a plain JSON shape, so the exporter, which
//! cannot link against this crate, can regenerate the circuit's Lean decode theorem from the
//! checked-in trace alone.
//!
//! The builder traced is the production one: for a wrapper, the `CircuitBuilder` that
//! already ran `add_recursive_verifiers` ([`TracingBuilder::over`]). The trace then holds
//! the rows and copies the traced gadgets added — with the rows' production indices, since
//! an arithmetic op can land in a free slot of a row the verifiers left — the constants and
//! virtual targets they use, the builder's counts when tracing began and a digest of the
//! whole builder state ([`state_digest`]). That lets the exporter replay the builder, check
//! it reached the same state, build it and certify the result (`built.rs`).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use std::collections::HashSet;

use plonky2::{
    field::types::{Field, PrimeField64},
    hash::{
        hash_types::{BytesHash, HashOutTarget},
        keccak::KeccakHash,
        poseidon2::Poseidon2Hash,
    },
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::Hasher,
        proof::ProofWithPublicInputsTarget,
    },
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
    /// The row's index in the builder.
    pub row: usize,
    /// `Gate::id()` of the placed gate.
    pub gate: String,
    /// The row's gate constants, canonical decimal.
    pub constants: Vec<String>,
}

/// The builder's counts of rows, copy constraints and virtual targets at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub rows: usize,
    pub copies: usize,
    pub virtual_targets: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCall {
    /// `select`, `not`, `and`, `or`, `add`, `sub`, `mul`, `is_equal`, `range_check`,
    /// `split_le`, `connect`, `assert_bool` (`add_virtual_bool_target_safe`),
    /// `poseidon2_hash`, `split_low_high` (recorded but not modeled by the exporter).
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

/// A `verify_proof` gadget the builder holds among the rows the trace does not list: the
/// child circuit is named by its own trace, and `public_inputs` are the parent targets that
/// carry the child's public inputs. The verifier key baked into the gadget is that of the
/// named circuit (production passes the built child's `VerifierCircuitData` to
/// `add_recursive_verifiers`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVerifier {
    pub child: String,
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub circuit: String,
    /// The builder's `CircuitConfig`, as `serde_json` renders it.
    pub config: serde_json::Value,
    /// [`state_digest`] of the traced builder.
    pub digest: String,
    /// The builder's counts when tracing began: what the recursive verifiers laid down.
    pub start: Counts,
    pub num_virtual_targets: usize,
    /// The rows the traced gadgets use, by production index: every row added from
    /// `start.rows` on, and the earlier rows whose free slots their ops landed in.
    pub rows: Vec<TraceRow>,
    /// The copy constraints added from `start.copies` on.
    pub copies: Vec<[String; 2]>,
    /// Constant targets and their values, sorted by target: those the traced gadgets
    /// allocated, and the earlier ones they use.
    pub constants: Vec<(String, String)>,
    pub public_inputs: Vec<String>,
    /// Targets of interest by role, so the Lean statement can refer to them.
    pub named: Vec<(String, Vec<String>)>,
    pub verifiers: Vec<TraceVerifier>,
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
        fn json<T: Serialize>(v: &T) -> String {
            serde_json::to_string(v).expect("serializable")
        }
        format!(
            "{{\n  \"circuit\": {},\n  \"config\": {},\n  \"digest\": {},\n  \"start\": {},\n  \
             \"num_virtual_targets\": {},\n  \"rows\": {},\n  \"copies\": {},\n  \
             \"constants\": {},\n  \"public_inputs\": {},\n  \"named\": {},\n  \
             \"verifiers\": {},\n  \"calls\": {}\n}}\n",
            json(&self.circuit),
            json(&self.config),
            json(&self.digest),
            json(&self.start),
            self.num_virtual_targets,
            list(&self.rows),
            list(&self.copies),
            list(&self.constants),
            list(&self.public_inputs),
            list(&self.named),
            list(&self.verifiers),
            list(&self.calls),
        )
    }

    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }

    /// The checked-in trace at `path` is this one. With `UPDATE_FORMAL_TRACE` set, writes it
    /// first; `regenerate` is the command the failure message names.
    pub fn assert_current(&self, path: &std::path::Path, regenerate: &str) {
        let json = self.to_json();
        let round_trip = Trace::from_json(&json).expect("trace round-trips");
        assert_eq!(round_trip.to_json(), json);
        std::println!(
            "{} trace: rows={} copies={} calls={} public_inputs={}",
            self.circuit,
            self.rows.len(),
            self.copies.len(),
            self.calls.len(),
            self.public_inputs.len()
        );
        if std::env::var_os("UPDATE_FORMAL_TRACE").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &json).unwrap();
        }
        let checked_in = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            checked_in == json,
            "{} is stale; regenerate with {regenerate}",
            path.display()
        );
    }
}

/// A `CircuitBuilder` that records the gadget calls made through [`GadgetBuilder`].
pub struct TracingBuilder {
    pub inner: CircuitBuilder<F, D>,
    pub calls: Vec<TraceCall>,
    pub verifiers: Vec<TraceVerifier>,
    start: Counts,
    /// The targets the calls and verifiers mention.
    used: HashSet<Target>,
}

impl TracingBuilder {
    /// Trace a fresh builder.
    pub fn new(config: CircuitConfig) -> Self {
        Self::over(CircuitBuilder::new(config))
    }

    /// Trace `inner` from its current state on: the production builder after
    /// `add_recursive_verifiers`. Name its `verify_proof` gadgets with [`Self::verifier`].
    pub fn over(inner: CircuitBuilder<F, D>) -> Self {
        let start = counts(&inner);
        TracingBuilder {
            inner,
            calls: Vec::new(),
            verifiers: Vec::new(),
            start,
            used: HashSet::new(),
        }
    }

    /// Record that `inner` holds a `verify_proof` gadget for a proof of the circuit whose
    /// trace is named `child`, with `proof.public_inputs` carrying the child's public
    /// inputs.
    pub fn verifier(&mut self, child: &str, proof: &ProofWithPublicInputsTarget<D>) {
        self.used.extend(&proof.public_inputs);
        self.verifiers.push(TraceVerifier {
            child: child.into(),
            public_inputs: proof
                .public_inputs
                .iter()
                .copied()
                .map(encode_target)
                .collect(),
        });
    }

    fn record<T>(
        &mut self,
        kind: &str,
        args: &[Target],
        bits: Option<usize>,
        f: impl FnOnce(&mut CircuitBuilder<F, D>) -> T,
        outs: impl FnOnce(&T) -> Vec<Target>,
    ) -> T {
        let before = counts(&self.inner);
        let r = f(&mut self.inner);
        let after = counts(&self.inner);
        let view = self.inner.formal_export_view();
        let fresh: Vec<Target> = (before.virtual_targets..after.virtual_targets)
            .map(|index| Target::VirtualTarget { index })
            .filter(|t| !view.constant_targets.contains_key(t))
            .collect();
        let outs = outs(&r);
        self.used.extend(args.iter().chain(&outs).chain(&fresh));
        self.calls.push(TraceCall {
            kind: kind.into(),
            args: args.iter().copied().map(encode_target).collect(),
            outs: outs.into_iter().map(encode_target).collect(),
            fresh: fresh.into_iter().map(encode_target).collect(),
            bits,
            rows: [before.rows, after.rows],
            copies: [before.copies, after.copies],
        });
        r
    }

    /// Snapshot the constraint system the traced gadgets added and the recorded calls.
    pub fn trace(&self, circuit: &str, named: Vec<(String, Vec<Target>)>) -> Trace {
        let digest = state_digest(&self.inner);
        let view = self.inner.formal_export_view();
        let copies = &view.copy_constraints[self.start.copies..];
        let referenced: HashSet<Target> = copies
            .iter()
            .flat_map(|c| [c.pair.0, c.pair.1])
            .chain(self.used.iter().copied())
            .chain(view.public_inputs.iter().copied())
            .chain(named.iter().flat_map(|(_, ts)| ts.iter().copied()))
            .collect();
        let rows: BTreeSet<usize> = referenced
            .iter()
            .filter_map(|t| match t {
                Target::Wire(w) => Some(w.row),
                Target::VirtualTarget { .. } => None,
            })
            .chain(self.start.rows..view.gate_instances.len())
            .collect();
        let constants: BTreeMap<String, String> = view
            .constant_targets
            .iter()
            .filter(|(t, _)| {
                referenced.contains(t)
                    || matches!(t, Target::VirtualTarget { index } if *index >= self.start.virtual_targets)
            })
            .map(|(t, v)| (encode_target(*t), format!("{}", v.to_canonical_u64())))
            .collect();
        Trace {
            circuit: circuit.into(),
            config: serde_json::to_value(&self.inner.config).expect("serializable"),
            digest,
            start: self.start,
            num_virtual_targets: view.num_virtual_targets,
            rows: rows
                .into_iter()
                .map(|row| {
                    let gi = &view.gate_instances[row];
                    TraceRow {
                        row,
                        gate: gi.gate_ref.0.id(),
                        constants: gi
                            .constants
                            .iter()
                            .map(|c| format!("{}", c.to_canonical_u64()))
                            .collect(),
                    }
                })
                .collect(),
            copies: copies
                .iter()
                .map(|c| [encode_target(c.pair.0), encode_target(c.pair.1)])
                .collect(),
            constants: constants.into_iter().collect(),
            public_inputs: view
                .public_inputs
                .iter()
                .copied()
                .map(encode_target)
                .collect(),
            named: named
                .into_iter()
                .map(|(n, ts)| (n, ts.into_iter().map(encode_target).collect()))
                .collect(),
            verifiers: self.verifiers.clone(),
            calls: self.calls.clone(),
        }
    }
}

/// Keccak-256, hex, of the builder's pre-`build` constraint system: every gate row with its
/// constants, the copy constraints, constant targets, public inputs and the virtual-target
/// count. Two builders with the same digest build the same circuit. The trace tests check
/// the traced builder's against the production constructor's, and the exporter checks its
/// replay's against the trace's.
pub fn state_digest(b: &CircuitBuilder<F, D>) -> String {
    let view = b.formal_export_view();
    assert!(
        view.lookups.iter().all(Vec::is_empty),
        "lookups are not modeled"
    );
    let felt = |n: usize| F::from_canonical_u64(n as u64);
    let target = |t: &Target| match *t {
        Target::Wire(w) => [felt(0), felt(w.row), felt(w.column)],
        Target::VirtualTarget { index } => [felt(1), felt(index), felt(0)],
    };
    let mut input = Vec::new();
    input.push(felt(view.gate_instances.len()));
    for gi in view.gate_instances {
        let id = gi.gate_ref.0.id();
        input.push(felt(id.len()));
        input.extend(id.bytes().map(|b| felt(b as usize)));
        input.push(felt(gi.constants.len()));
        input.extend(&gi.constants);
    }
    input.push(felt(view.copy_constraints.len()));
    for c in view.copy_constraints {
        input.extend(target(&c.pair.0));
        input.extend(target(&c.pair.1));
    }
    let constants: BTreeMap<String, (&Target, &F)> = view
        .constant_targets
        .iter()
        .map(|(t, v)| (encode_target(*t), (t, v)))
        .collect();
    input.push(felt(constants.len()));
    for (t, v) in constants.values() {
        input.extend(target(t));
        input.push(**v);
    }
    input.push(felt(view.public_inputs.len()));
    for t in view.public_inputs {
        input.extend(target(t));
    }
    input.push(felt(view.num_virtual_targets));
    let BytesHash(bytes) = KeccakHash::<32>::hash_no_pad(&input);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn counts(b: &CircuitBuilder<F, D>) -> Counts {
    let v = b.formal_export_view();
    Counts {
        rows: v.gate_instances.len(),
        copies: v.copy_constraints.len(),
        virtual_targets: v.num_virtual_targets,
    }
}

impl GadgetBuilder<F, D> for TracingBuilder {
    fn add_virtual_target(&mut self) -> Target {
        self.inner.add_virtual_target()
    }
    fn add_virtual_targets(&mut self, n: usize) -> Vec<Target> {
        self.inner.add_virtual_targets(n)
    }
    fn add_virtual_public_input(&mut self) -> Target {
        self.inner.add_virtual_public_input()
    }
    fn add_virtual_hash(&mut self) -> HashOutTarget {
        self.inner.add_virtual_hash()
    }
    fn add_virtual_hash_public_input(&mut self) -> HashOutTarget {
        self.inner.add_virtual_hash_public_input()
    }
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
    fn _true(&mut self) -> BoolTarget {
        self.inner._true()
    }
    fn constant_bool(&mut self, b: bool) -> BoolTarget {
        self.inner.constant_bool(b)
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
    fn mul_const(&mut self, c: F, x: Target) -> Target {
        let c = self.inner.constant(c);
        GadgetBuilder::mul(self, c, x)
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
    fn connect_hashes(&mut self, x: HashOutTarget, y: HashOutTarget) {
        for i in 0..4 {
            GadgetBuilder::connect(self, x.elements[i], y.elements[i]);
        }
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
    fn split_le(&mut self, x: Target, num_bits: usize) -> Vec<BoolTarget> {
        self.record(
            "split_le",
            &[x],
            Some(num_bits),
            |bd| bd.split_le(x, num_bits),
            |bits| bits.iter().map(|b| b.target).collect(),
        )
    }
    fn split_low_high(&mut self, x: Target, n_log: usize, num_bits: usize) -> (Target, Target) {
        self.record(
            "split_low_high",
            &[x],
            Some(n_log),
            |bd| bd.split_low_high(x, n_log, num_bits),
            |&(lo, hi)| alloc::vec![lo, hi],
        )
    }
    fn register_public_input(&mut self, target: Target) {
        self.inner.register_public_input(target)
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
