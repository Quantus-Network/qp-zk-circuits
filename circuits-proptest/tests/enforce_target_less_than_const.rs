//! Property tests for `enforce_target_less_than_const`.
//!
//! `enforce_target_less_than_const(target, upper, n_log)` should accept the
//! witness iff `target < upper`, plus range-check `target` to `n_log` bits.
//!
//! * `assumptions`: `upper > 0` and `upper - 1 < 2^n_log`.
//! * `spec`: the prover should succeed iff `target < upper`.
//! * `soundness`: honest in-range `target` ⇒ prover accepts.
//! * `completeness`: `target >= upper` ⇒ prover rejects (gadget assertion or
//!   `split_le` range check, depending on the value).

use circuits_proptest::{harness::prove_gadget, strategies::arb_n_log};
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use proptest::prelude::*;
use zk_circuits_common::{
    circuit::{D, F},
    gadgets::enforce_target_less_than_const,
};

/// Pure-Rust spec: prover should accept iff `target < upper`.
fn spec(target: u64, upper: u64) -> bool {
    target < upper
}

/// `(n_log, upper, target)` where `upper - 1 < 2^n_log` (gadget assumption)
/// and `target < upper` (within spec).
fn arb_in_range_inputs() -> impl Strategy<Value = (usize, usize, u64)> {
    arb_n_log().prop_flat_map(|n_log| {
        // `upper` must be in `1..=2^n_log` so `upper-1` fits in n_log bits.
        let upper_max = if n_log >= usize::BITS as usize {
            usize::MAX
        } else {
            1usize << n_log
        };
        (1usize..=upper_max).prop_flat_map(move |upper| {
            (Just(n_log), Just(upper), 0u64..(upper as u64))
        })
    })
}

/// `(n_log, upper, target)` where `target >= upper` but still fits in n_log bits
/// (so the rejection comes from the gadget's own assertion, not the
/// range-check). Tests pure spec-violation rejection.
fn arb_above_range_inputs() -> impl Strategy<Value = (usize, usize, u64)> {
    arb_n_log().prop_flat_map(|n_log| {
        let upper_max = if n_log >= usize::BITS as usize {
            usize::MAX
        } else {
            1usize << n_log
        };
        // Need at least one valid `target >= upper` that still fits in n_log bits,
        // i.e. `upper <= 2^n_log - 1`.
        (1usize..upper_max).prop_flat_map(move |upper| {
            let max_in_bits = (upper_max - 1) as u64;
            (Just(n_log), Just(upper), (upper as u64)..=max_in_bits)
        })
    })
}

fn build_enforce_circuit(
    builder: &mut CircuitBuilder<F, D>,
    upper: usize,
    n_log: usize,
) -> Target {
    let target = builder.add_virtual_target();
    enforce_target_less_than_const(builder, target, upper, n_log);
    target
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        ..ProptestConfig::default()
    })]

    /// SOUNDNESS: in-range targets are accepted.
    #[test]
    fn accepts_in_range((n_log, upper, target) in arb_in_range_inputs()) {
        prop_assume!(spec(target, upper as u64));
        let result = prove_gadget(
            |builder| build_enforce_circuit(builder, upper, n_log),
            |pw, &t| pw.set_target(t, F::from_canonical_u64(target)),
        );
        prop_assert!(
            result.is_ok(),
            "prove failed for in-range target (n_log={n_log}, upper={upper}, target={target}): {:?}",
            result.err(),
        );
    }

    /// COMPLETENESS: targets at or above the bound are rejected.
    #[test]
    fn rejects_at_or_above_bound((n_log, upper, target) in arb_above_range_inputs()) {
        prop_assume!(!spec(target, upper as u64));
        let result = prove_gadget(
            |builder| build_enforce_circuit(builder, upper, n_log),
            |pw, &t| pw.set_target(t, F::from_canonical_u64(target)),
        );
        prop_assert!(
            result.is_err(),
            "prover accepted out-of-bound target (n_log={n_log}, upper={upper}, target={target})",
        );
    }
}
