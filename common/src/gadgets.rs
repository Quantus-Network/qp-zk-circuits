use alloc::{vec, vec::Vec};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

fn assert_comparison_width(left: usize, n_log: usize) {
    assert!(n_log > 0, "comparison bit width must be greater than zero");
    // Goldilocks elements are < 2^64. Widths above 64 have no unique meaning as
    // integer comparisons over field targets; reject them up front.
    assert!(
        n_log <= 64,
        "comparison bit width {n_log} exceeds 64 bits (Goldilocks field elements)"
    );

    let exclusive_upper_bound = if n_log >= usize::BITS as usize {
        usize::MAX
    } else {
        1usize << n_log
    };

    assert!(
        left < exclusive_upper_bound,
        "left constant {left} does not fit in comparison width {n_log} bits"
    );
}

/// Compares a constant integer `left` with a variable `right` in a circuit, and returns whether
/// or not `left < right`.
///
/// `n_log` must be wide enough to represent `left`, and it also range-constrains `right` to
/// `n_log` bits. Widths up to 63 use `split_le` (unique: `2^n_log < p`). Width 64 goes through
/// [`split_canonical_u32_halves`] so the Goldilocks wraparound alias `x + p` cannot flip the
/// comparison — a plain `split_le(right, 64)` would admit both decompositions.
///
/// # Returns
/// - `BoolTarget`: True if `left < right`, false otherwise.
pub fn is_const_less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: usize,
    right: Target,
    n_log: usize,
) -> BoolTarget {
    assert_comparison_width(left, n_log);

    // 64-bit splits over Goldilocks are not unique: for small `x`, both `x` and
    // `x + p` are valid 64-bit bit-patterns of the same field element. Compare
    // via the canonical half-split so a malicious prover cannot witness the
    // alias (e.g. decompose `right = 0` as `p`) and flip `left < right`.
    if n_log == 64 {
        return is_const_less_than_canonical_u64(builder, left as u64, right);
    }

    let right_bits = builder.split_le(right, n_log);
    let left_bits: Vec<bool> = (0..n_log).map(|i| ((left >> i) & 1) != 0).collect();

    let mut lt = builder._false();
    let mut eq = builder._true();

    for i in (0..n_log).rev() {
        let a = builder.constant_bool(left_bits[i]);
        let b = right_bits[i];

        let not_a = builder.not(a);
        let not_a_and_b = builder.and(not_a, b);
        let this_lt = builder.and(not_a_and_b, eq);
        lt = builder.or(lt, this_lt);

        let a_xor_b = xor(builder, a, b);
        let not_xor = builder.not(a_xor_b);
        eq = builder.and(eq, not_xor);
    }

    lt
}

/// `left < right` for a 64-bit comparison, with `right` forced into its unique
/// canonical 32-bit half decomposition (see [`split_canonical_u32_halves`]).
fn is_const_less_than_canonical_u64<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: u64,
    right: Target,
) -> BoolTarget {
    let (right_lo, right_hi) = split_canonical_u32_halves(builder, right);
    let left_lo = builder.constant(F::from_canonical_u64(left & 0xFFFF_FFFF));
    let left_hi = builder.constant(F::from_canonical_u64(left >> 32));

    // left < right ⇔ left_hi < right_hi ∨ (left_hi = right_hi ∧ left_lo < right_lo)
    let hi_lt = u32_lt(builder, left_hi, right_hi);
    let lo_lt = u32_lt(builder, left_lo, right_lo);
    let hi_eq = builder.is_equal(left_hi, right_hi);
    let lo_lt_and_hi_eq = builder.and(hi_eq, lo_lt);
    builder.or(hi_lt, lo_lt_and_hi_eq)
}

/// Enforce `target < upper_bound_exclusive`.
///
/// This helper also constrains `target` to the minimum bit width implied by `n_log`.
pub fn enforce_target_less_than_const<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target: Target,
    upper_bound_exclusive: usize,
    n_log: usize,
) {
    assert!(
        upper_bound_exclusive > 0,
        "exclusive upper bound must be greater than zero"
    );
    assert_comparison_width(upper_bound_exclusive - 1, n_log);

    let overflow = is_const_less_than(builder, upper_bound_exclusive - 1, target, n_log);
    let zero = builder.zero();
    builder.connect(overflow.target, zero);
}

/// Computes the XOR of two boolean values in a circuit.
///
/// The following mathematical expression is used:
///
/// ```text
/// a XOR b = a + b - 2ab
/// ```
///
/// # Returns
/// - `BoolTarget`: The value given by XORing `a` and `b`.
fn xor<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: BoolTarget,
    b: BoolTarget,
) -> BoolTarget {
    let a_t = a.target;
    let b_t = b.target;
    let ab = builder.mul(a_t, b_t);
    let two_ab = builder.mul_const(F::from_canonical_u32(2), ab);
    let a_plus_b = builder.add(a_t, b_t);
    let xor = builder.sub(a_plus_b, two_ab);
    BoolTarget::new_unsafe(xor)
}

/// Compare two 4-element arrays (e.g., hash outputs) for equality.
#[inline]
pub fn bytes_digest_eq<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    a: [Target; 4],
    c: [Target; 4],
) -> BoolTarget {
    // limb-wise equality in the field
    let e0 = b.is_equal(a[0], c[0]); // BoolTarget
    let e1 = b.is_equal(a[1], c[1]);
    let e2 = b.is_equal(a[2], c[2]);
    let e3 = b.is_equal(a[3], c[3]);
    let e01 = b.and(e0, e1);
    let e23 = b.and(e2, e3);
    b.and(e01, e23)
}

#[inline]
pub fn limbs4_at_offset<const LEAF_PI_LEN: usize, const KEY_OFFSET: usize>(
    pis: &[Target],
    index: usize,
) -> [Target; 4] {
    let base = index * LEAF_PI_LEN + KEY_OFFSET;
    [pis[base], pis[base + 1], pis[base + 2], pis[base + 3]]
}

#[inline]
pub fn limb1_at_offset<const LEAF_PI_LEN: usize, const KEY_OFFSET: usize>(
    pis: &[Target],
    index: usize,
) -> Target {
    let base = index * LEAF_PI_LEN + KEY_OFFSET;
    pis[base]
}

// NOTE: `pack_le_32x2` and `digest4_from_le32x8` (32-bit-limb packing helpers
// from an older implementation) were removed: they had no callers and did not
// range-check their limbs in-circuit, so the documented 32-bit domain — and
// with it the injectivity of the reconstruction — was unenforced (a prover
// could reach a chosen packed value via modular wraparound). If limb packing
// is reintroduced, it must range-check both limbs to 32 bits AND exclude the
// Goldilocks wraparound region (`hi == 2^32 - 1 && lo >= 1`).

/// Compare two 32-bit values: returns `x < y`.
///
/// Both inputs must already be range-constrained to 32 bits by the caller
/// (e.g. as outputs of `split_low_high`). Computes `t = x + 2^32 - y`, which
/// lies in `[1, 2^33 - 1]` (no field wraparound: `2^33 < p`); bit 32 of `t`
/// is exactly `x >= y`.
fn u32_lt<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
) -> BoolTarget {
    let two_pow_32 = b.constant(F::from_canonical_u64(1 << 32));
    let x_shifted = b.add(x, two_pow_32);
    let t = b.sub(x_shifted, y);
    // high part is a single bit, range-checked to 1 bit by split_low_high.
    let (_low, ge_bit) = b.split_low_high(t, 32, 33);
    let ge = BoolTarget::new_unsafe(ge_bit);
    b.not(ge)
}

/// Split a field element into 32-bit halves, enforcing the CANONICAL
/// decomposition.
///
/// `split_low_high(x, 32, 64)` alone admits two valid decompositions for
/// values below `2^64 - p = 2^32 - 1`: the canonical one and `x + p`. The
/// non-canonical representative always lands in the wraparound region
/// `hi == 2^32 - 1 && lo >= 1` (exactly the integers `>= p` expressible in
/// 32-bit halves), so excluding that region makes the decomposition unique
/// and comparisons built on it sound against malicious provers.
fn split_canonical_u32_halves<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: Target,
) -> (Target, Target) {
    let (lo, hi) = b.split_low_high(x, 32, 64);

    let max_hi = b.constant(F::from_canonical_u64((1u64 << 32) - 1));
    let hi_is_max = b.is_equal(hi, max_hi);
    let zero = b.zero();
    let lo_is_zero = b.is_equal(lo, zero);
    let lo_nonzero = b.not(lo_is_zero);
    let in_wraparound = b.and(hi_is_max, lo_nonzero);
    b.connect(in_wraparound.target, zero);

    (lo, hi)
}

/// Route 4-limb digests through an odd-even adjacent-swap network.
///
/// Each switch is a private boolean target. Both complete digests are either
/// passed through or swapped, so every output is structurally an exact
/// permutation of the inputs for every valid witness. The circuit does not
/// constrain which permutation is chosen.
pub fn permute_digests4<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    values: Vec<[Target; 4]>,
) -> (Vec<[Target; 4]>, Vec<BoolTarget>) {
    let n = values.len();
    if n <= 1 {
        return (values, Vec::new());
    }

    let mut routed = values;
    let mut switches = Vec::with_capacity(n * (n - 1) / 2);

    for round in 0..n {
        let mut i = round % 2;
        while i + 1 < n {
            let swap = b.add_virtual_bool_target_safe();
            let lhs = routed[i];
            let rhs = routed[i + 1];
            for j in 0..4 {
                routed[i][j] = b.select(swap, rhs[j], lhs[j]);
                routed[i + 1][j] = b.select(swap, lhs[j], rhs[j]);
            }
            switches.push(swap);
            i += 2;
        }
    }

    (routed, switches)
}

/// Compute switch witnesses that route input indices into `permutation`,
/// where `permutation[output_index]` is the input index for that output.
///
/// Returns `None` unless the slice is an exact permutation of `0..len`.
pub fn permutation_switches(permutation: &[usize]) -> Option<Vec<bool>> {
    let n = permutation.len();
    let mut destination = vec![usize::MAX; n];
    for (output_index, &input_index) in permutation.iter().enumerate() {
        if input_index >= n || destination[input_index] != usize::MAX {
            return None;
        }
        destination[input_index] = output_index;
    }

    let mut current: Vec<usize> = (0..n).collect();
    let mut switches = Vec::with_capacity(n.saturating_mul(n.saturating_sub(1)) / 2);
    for round in 0..n {
        let mut i = round % 2;
        while i + 1 < n {
            let swap = destination[current[i]] > destination[current[i + 1]];
            switches.push(swap);
            if swap {
                current.swap(i, i + 1);
            }
            i += 2;
        }
    }

    debug_assert_eq!(current, permutation);
    Some(switches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{wormhole_private_batch_circuit_config, C, D, F};
    use alloc::vec;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    /// Build `is_const_less_than(left, right, n_log)` as a public bool and prove it
    /// for the given `right` value; return the proved boolean.
    fn prove_const_lt(left: usize, right: u64, n_log: usize) -> bool {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let right_t = b.add_virtual_target();
        let lt = is_const_less_than(&mut b, left, right_t, n_log);
        b.register_public_input(lt.target);
        let data = b.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(right_t, F::from_canonical_u64(right))
            .unwrap();
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();
        proof.public_inputs[0].to_canonical_u64() == 1
    }

    /// Narrow widths (`n_log < 64`) keep the `split_le` bit-comparator path;
    /// uniqueness is free because `2^n_log < p`.
    #[test]
    fn is_const_less_than_narrow_width_matches_native() {
        assert!(!prove_const_lt(3, 3, 8));
        assert!(prove_const_lt(3, 4, 8));
        assert!(!prove_const_lt(0, 0, 1));
        assert!(prove_const_lt(0, 1, 1));
    }

    /// The 64-bit path must go through the canonical half-split: a plain
    /// `split_le(right, 64)` would let a prover decompose `right = 0` as the
    /// 64-bit integer `p` and flip `0 < right` to true. These cases pin the
    /// honest comparison, including against the wraparound-adjacent values
    /// (`1`, `2^32 - 2`, `p - 1`) that sit next to the excluded alias region.
    #[test]
    fn is_const_less_than_u64_matches_native_and_rejects_zero_alias() {
        const P: u64 = 0xFFFF_FFFF_0000_0001;
        assert!(
            !prove_const_lt(0, 0, 64),
            "0 < 0 must be false; accepting bits-of-p for right=0 would flip this"
        );
        assert!(prove_const_lt(0, 1, 64));
        assert!(!prove_const_lt(1, 1, 64));
        assert!(prove_const_lt(1, 2, 64));
        // Largest canonical field element (hi = 2^32 - 1, lo = 0 — the edge of
        // the excluded wraparound region `hi == 2^32 - 1 && lo >= 1`).
        assert!(prove_const_lt(0, P - 1, 64));
        assert!(prove_const_lt((P - 2) as usize, P - 1, 64));
        assert!(!prove_const_lt((P - 1) as usize, P - 1, 64));
    }

    /// Forcing `0 < right` while witnessing `right = 0` must be unsatisfiable.
    /// Without the wraparound exclusion a malicious prover could satisfy this
    /// by decomposing 0 as the 64-bit integer `p`.
    #[test]
    fn is_const_less_than_u64_cannot_prove_zero_less_than_zero() {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let right_t = b.add_virtual_target();
        let lt = is_const_less_than(&mut b, 0, right_t, 64);
        let tru = b._true();
        b.connect(lt.target, tru.target);
        let data = b.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(right_t, F::ZERO).unwrap();
        assert!(
            data.prove(pw).is_err(),
            "proving 0 < 0 via a 64-bit alias of zero must fail"
        );
    }

    #[test]
    #[should_panic(expected = "exceeds 64 bits")]
    fn is_const_less_than_rejects_width_above_64() {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let right_t = b.add_virtual_target();
        let _ = is_const_less_than(&mut b, 0, right_t, 65);
    }

    /// Gates added by `permute_digests4` over `n` virtual digests under the
    /// production private-batch circuit config.
    fn permutation_gate_cost(n: usize) -> usize {
        let mut b = CircuitBuilder::<F, D>::new(wormhole_private_batch_circuit_config());
        let values: Vec<[Target; 4]> = (0..n)
            .map(|_| core::array::from_fn(|_| b.add_virtual_target()))
            .collect();
        let before = b.num_gates();
        let _ = permute_digests4(&mut b, values);
        b.num_gates() - before
    }

    #[test]
    fn permute_digests4_gate_cost_stays_small() {
        for (n, budget) in [(7usize, 30), (64usize, 2_500)] {
            let cost = permutation_gate_cost(n);
            assert!(
                cost <= budget,
                "n={n}: {cost} gates exceeds budget {budget}"
            );
        }
    }

    #[test]
    fn permute_digests4_routes_complete_digests() {
        let inputs: Vec<[u64; 4]> = vec![
            [10, 11, 12, 13],
            [20, 21, 22, 23],
            [30, 31, 32, 33],
            [40, 41, 42, 43],
        ];
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let targets: Vec<[Target; 4]> = (0..inputs.len())
            .map(|_| core::array::from_fn(|_| b.add_virtual_target()))
            .collect();
        let (permuted, switches) = permute_digests4(&mut b, targets.clone());
        for digest in permuted {
            for t in digest {
                b.register_public_input(t);
            }
        }
        let data = b.build::<C>();

        for permutation in [
            vec![0, 1, 2, 3],
            vec![3, 2, 1, 0],
            vec![2, 0, 3, 1],
            vec![1, 3, 0, 2],
        ] {
            let mut pw = PartialWitness::new();
            for (digest_t, digest_v) in targets.iter().zip(&inputs) {
                for (t, v) in digest_t.iter().zip(digest_v) {
                    pw.set_target(*t, F::from_canonical_u64(*v)).unwrap();
                }
            }
            for (target, value) in switches
                .iter()
                .zip(permutation_switches(&permutation).unwrap())
            {
                pw.set_target(target.target, F::from_bool(value)).unwrap();
            }
            let proof = data.prove(pw).unwrap();
            data.verify(proof.clone()).unwrap();

            let expected: Vec<[u64; 4]> = permutation.iter().map(|&i| inputs[i]).collect();
            let proved: Vec<[u64; 4]> = proof
                .public_inputs
                .chunks_exact(4)
                .map(|c| core::array::from_fn(|i| c[i].to_canonical_u64()))
                .collect();
            assert_eq!(proved, expected);
        }
    }

    #[test]
    fn permutation_switches_rejects_invalid_indices() {
        assert!(permutation_switches(&[0, 0]).is_none());
        assert!(permutation_switches(&[0, 2]).is_none());
    }

    #[test]
    fn permutation_switches_routes_every_four_element_permutation() {
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let permutation = [a, b, c, d];
                        let Some(switches) = permutation_switches(&permutation) else {
                            continue;
                        };

                        let mut current = vec![0, 1, 2, 3];
                        let mut switch_index = 0;
                        for round in 0..4 {
                            let mut i = round % 2;
                            while i + 1 < 4 {
                                if switches[switch_index] {
                                    current.swap(i, i + 1);
                                }
                                switch_index += 1;
                                i += 2;
                            }
                        }
                        assert_eq!(current, permutation);
                    }
                }
            }
        }
    }
}
