//! Property tests for `is_const_less_than`.
//!
//! Modeled on the Clean `FormalCircuit` decomposition:
//! * `assumptions`: `left < 2^n_log` and `right < 2^n_log` (both fit in n_log bits).
//! * `spec`: gadget output is `1` iff `left < right`, else `0`.
//! * `soundness`: for honest inputs respecting `assumptions`, the prover accepts
//!   AND the gadget's output equals the spec.
//! * `completeness`: if the witness violates the bit-width assumption on `right`,
//!   the prover rejects (the gadget's `split_le` range check trips).
//!
//! We also verify that the gadget cannot be coerced into producing a wrong output
//! by connecting it to the negation of the spec (an adversarial-prover check).

use circuits_proptest::{
    harness::prove_gadget,
    strategies::{arb_n_log, arb_u64_in_bits, arb_u64_out_of_bits, arb_usize_in_bits},
};
use plonky2::{
    field::types::Field,
    iop::target::Target,
    iop::witness::WitnessWrite,
    plonk::circuit_builder::CircuitBuilder,
};
use proptest::prelude::*;
use zk_circuits_common::{
    circuit::{D, F},
    gadgets::is_const_less_than,
};

/// Pure-Rust spec: returns the boolean the gadget should produce.
fn spec(left: usize, right: u64) -> bool {
    (left as u64) < right
}

/// Strategy producing `(n_log, left, right)` triples that satisfy the gadget's
/// assumptions: both `left` and `right` fit in `n_log` bits.
fn arb_valid_inputs() -> impl Strategy<Value = (usize, usize, u64)> {
    arb_n_log().prop_flat_map(|n_log| {
        (
            Just(n_log),
            arb_usize_in_bits(n_log),
            arb_u64_in_bits(n_log),
        )
    })
}

/// Strategy producing `(n_log, left, right)` where `left` honestly fits but
/// `right` exceeds `2^n_log`. Cap below Goldilocks order so `from_canonical_u64`
/// stays canonical and we don't accidentally wrap into a value that fits.
fn arb_right_out_of_bits() -> impl Strategy<Value = (usize, usize, u64)> {
    // Goldilocks order p = 2^64 - 2^32 + 1; cap inputs strictly below p so
    // canonical reduction is the identity.
    const GOLDILOCKS_MAX_CANONICAL: u64 = 0xFFFF_FFFF_0000_0000;
    (1usize..=31).prop_flat_map(|n_log| {
        (
            Just(n_log),
            arb_usize_in_bits(n_log),
            arb_u64_out_of_bits(n_log).prop_filter(
                "right must be canonical Goldilocks",
                move |&v| v <= GOLDILOCKS_MAX_CANONICAL,
            ),
        )
    })
}

fn build_lt_circuit(
    builder: &mut CircuitBuilder<F, D>,
    left: usize,
    n_log: usize,
    expected: bool,
) -> Target {
    let right = builder.add_virtual_target();
    let lt = is_const_less_than(builder, left, right, n_log);
    let expected_const = builder.constant_bool(expected);
    builder.connect(lt.target, expected_const.target);
    right
}

proptest! {
    // Each prove() call builds a small circuit; default 256 cases is overkill.
    #![proptest_config(ProptestConfig {
        cases: 32,
        ..ProptestConfig::default()
    })]

    /// SOUNDNESS + COMPLETENESS-on-honest-inputs: for any inputs satisfying the
    /// width assumption, the gadget output equals the spec, and the prover
    /// accepts when we connect the output to the spec value.
    #[test]
    fn output_matches_spec_on_honest_inputs((n_log, left, right) in arb_valid_inputs()) {
        let expected = spec(left, right);
        let result = prove_gadget(
            |builder| build_lt_circuit(builder, left, n_log, expected),
            |pw, &right_target| pw.set_target(right_target, F::from_canonical_u64(right)),
        );
        prop_assert!(
            result.is_ok(),
            "prove failed for honest inputs (n_log={n_log}, left={left}, right={right}): {:?}",
            result.err(),
        );
    }

    /// ADVERSARIAL SOUNDNESS: if we lie about the gadget's output (connect it
    /// to the negation of the spec), the prover MUST reject. Catches a class of
    /// bug where the gadget output is unconstrained or over-permissive.
    #[test]
    fn rejects_lying_about_output((n_log, left, right) in arb_valid_inputs()) {
        let lie = !spec(left, right);
        let result = prove_gadget(
            |builder| build_lt_circuit(builder, left, n_log, lie),
            |pw, &right_target| pw.set_target(right_target, F::from_canonical_u64(right)),
        );
        prop_assert!(
            result.is_err(),
            "prover accepted a lying witness (n_log={n_log}, left={left}, right={right}, claimed={lie})",
        );
    }

    /// COMPLETENESS-on-bad-inputs: if `right` exceeds `n_log` bits, the
    /// gadget's `split_le` range check must trip. The expected boolean is
    /// irrelevant — the circuit should reject regardless.
    #[test]
    fn rejects_out_of_range_right((n_log, left, right) in arb_right_out_of_bits()) {
        // Pick either claimed-output; both should be rejected by the range check.
        for &claimed in &[false, true] {
            let result = prove_gadget(
                |builder| build_lt_circuit(builder, left, n_log, claimed),
                |pw, &right_target| pw.set_target(right_target, F::from_canonical_u64(right)),
            );
            prop_assert!(
                result.is_err(),
                "prover accepted out-of-range right (n_log={n_log}, left={left}, right={right}, claimed={claimed})",
            );
        }
    }
}
