//! Reusable proptest strategies for ZK gadget tests.
//!
//! All strategies bias toward boundary values (0, MAX, off-by-one) because that's
//! where soundness bugs hide. See the proptest "tips and best practices" notes
//! and the "strategies the hard way" article for the design pattern.

use plonky2::field::types::Field;
use proptest::prelude::*;
use zk_circuits_common::circuit::F;

/// Maximum bit width that callers should request. `n_log == 64` is the largest a
/// `usize` constant can practically address on 64-bit platforms; larger widths
/// exceed Goldilocks anyway.
pub const MAX_N_LOG: usize = 32;

/// Strategy for an `n_log` value usable by `is_const_less_than` /
/// `enforce_target_less_than_const`. Avoids `0` (the gadget asserts on it) and
/// caps at `MAX_N_LOG` so test circuits stay small.
pub fn arb_n_log() -> impl Strategy<Value = usize> {
    1usize..=MAX_N_LOG
}

/// Strategy for a `usize` constrained to fit in `n_log` bits, biased toward
/// boundary values: `0`, `2^n_log - 1`, and a uniform middle range.
pub fn arb_usize_in_bits(n_log: usize) -> impl Strategy<Value = usize> {
    let exclusive_upper = if n_log >= usize::BITS as usize {
        usize::MAX
    } else {
        1usize << n_log
    };
    let max = exclusive_upper.saturating_sub(1);
    prop_oneof![
        2 => Just(0usize),
        2 => Just(max),
        1 => Just(max.saturating_sub(1)),
        5 => 0usize..=max,
    ]
}

/// Strategy for a `u64` constrained to fit in `n_log` bits, biased toward
/// boundary values. Returned as `u64` so callers can also exercise values that
/// overflow `usize` on 32-bit hosts (Goldilocks fits comfortably).
pub fn arb_u64_in_bits(n_log: usize) -> impl Strategy<Value = u64> {
    let exclusive_upper = if n_log >= 64 {
        u64::MAX
    } else {
        1u64 << n_log
    };
    let max = exclusive_upper.saturating_sub(1);
    prop_oneof![
        2 => Just(0u64),
        2 => Just(max),
        1 => Just(max.saturating_sub(1)),
        5 => 0u64..=max,
    ]
}

/// Strategy for a `u64` value that **exceeds** `n_log` bits. Used to test
/// completeness: the circuit must reject these.
pub fn arb_u64_out_of_bits(n_log: usize) -> impl Strategy<Value = u64> {
    assert!(n_log < 64, "cannot generate values out of 64-bit range");
    let lower = 1u64 << n_log;
    lower..=u64::MAX
}

/// Strategy for an arbitrary canonical Goldilocks field element.
pub fn arb_field_element() -> impl Strategy<Value = F> {
    prop_oneof![
        2 => Just(F::ZERO),
        2 => Just(F::ONE),
        1 => Just(F::NEG_ONE),
        5 => any::<u64>().prop_map(F::from_noncanonical_u64),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn arb_usize_in_bits_respects_bound(n_log in arb_n_log(), v in arb_usize_in_bits(8)) {
            let _ = n_log;
            prop_assert!(v <= 0xFF);
        }

        #[test]
        fn arb_u64_out_of_bits_actually_exceeds(n_log in 1usize..=32, v in arb_u64_out_of_bits(8)) {
            let _ = n_log;
            prop_assert!(v >= 1u64 << 8);
        }
    }
}
