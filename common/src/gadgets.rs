use alloc::vec::Vec;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

fn assert_comparison_width(left: usize, n_log: usize) {
    assert!(n_log > 0, "comparison bit width must be greater than zero");

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
/// `n_log` bits via `split_le`.
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

/// Compare two field elements as 64-bit integers: returns `(x < y, x == y)`.
///
/// Each element is split into range-checked, canonicity-enforced 32-bit
/// halves (see [`split_canonical_u32_halves`]) and compared high-half first,
/// so the comparison result is sound even against a malicious prover that
/// hand-picks witness values for the split targets.
fn felt64_lt_eq<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
) -> (BoolTarget, BoolTarget) {
    let (x_lo, x_hi) = split_canonical_u32_halves(b, x);
    let (y_lo, y_hi) = split_canonical_u32_halves(b, y);

    let hi_lt = u32_lt(b, x_hi, y_hi);
    let hi_eq = b.is_equal(x_hi, y_hi);
    let lo_lt = u32_lt(b, x_lo, y_lo);

    // lt = hi_lt OR (hi_eq AND lo_lt)
    let lo_decides = b.and(hi_eq, lo_lt);
    let lt = b.or(hi_lt, lo_decides);
    let eq = b.is_equal(x, y);
    (lt, eq)
}

/// Compare two 4-limb digests lexicographically (limb 0 most significant),
/// treating each limb as a canonical 64-bit integer: returns `a < b`.
///
/// Sound against malicious provers: every limb split is canonicity-enforced
/// (see [`split_canonical_u32_halves`]), so the comparison result is fully
/// constrained by the input values.
pub fn digest4_lt<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    lhs: [Target; 4],
    rhs: [Target; 4],
) -> BoolTarget {
    // Fold from the least-significant limb up:
    // lt = lt_0 OR (eq_0 AND (lt_1 OR (eq_1 AND ...)))
    let mut lt = b._false();
    for i in (0..4).rev() {
        let (lt_i, eq_i) = felt64_lt_eq(b, lhs[i], rhs[i]);
        let carry = b.and(eq_i, lt);
        lt = b.or(lt_i, carry);
    }
    lt
}

/// Lexicographic `lhs < rhs` over 8 range-checked 32-bit half-limbs (most
/// significant first). Inputs must already be range-constrained to 32 bits;
/// no splits are performed here (see [`sort_digests4`]).
fn halves8_lt<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    lhs: &[Target; 8],
    rhs: &[Target; 8],
) -> BoolTarget {
    // Fold from the least-significant half up:
    // lt = lt_0 OR (eq_0 AND (lt_1 OR (eq_1 AND ...)))
    let mut lt = b._false();
    for i in (0..8).rev() {
        let lt_i = u32_lt(b, lhs[i], rhs[i]);
        let eq_i = b.is_equal(lhs[i], rhs[i]);
        let carry = b.and(eq_i, lt);
        lt = b.or(lt_i, carry);
    }
    lt
}

/// Sort 4-limb digests ascending (lexicographic, limb 0 most significant)
/// with an odd-even transposition network of compare-and-swap stages.
///
/// Range-check work is hoisted out of the quadratic part: each digest limb is
/// split into canonical 32-bit halves ONCE at ingress (4 splits per digest),
/// the 8-half representation is routed through the O(n²) comparator network
/// (comparators use only [`u32_lt`], no further splits), and the halves are
/// recombined into limbs at egress. Re-splitting inside every comparator, as
/// a naive implementation would, costs ~3x more gates.
///
/// Two layers of guarantees:
///
/// 1. The output is ALWAYS a permutation of the input: `split_low_high`
///    constrains `limb = lo + hi * 2^32`, each comparator emits
///    `select(lt, a, b)` / `select(lt, b, a)` — which is `{a, b}` as a
///    multiset for either value of the (boolean-constrained) flag, moving
///    each digest's 8 halves under one flag — and egress recombination
///    computes exactly `hi * 2^32 + lo`. So each output digest equals some
///    input digest independent of any comparison correctness.
/// 2. The ascending ORDER is also enforced against malicious provers: the
///    ingress splits are canonicity-constrained (see
///    [`split_canonical_u32_halves`], which excludes the `x + p` alias), the
///    comparators only ever route these constrained halves, so no witness
///    choice can flip a comparison and mis-order the output.
///
/// The recombination here satisfies the packing rules noted above (limbs
/// range-checked AND wraparound region excluded): both come from the ingress
/// canonical split.
pub fn sort_digests4<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    values: Vec<[Target; 4]>,
) -> Vec<[Target; 4]> {
    let n = values.len();
    if n <= 1 {
        return values;
    }

    // Ingress: one canonical split per limb. Halves are ordered most
    // significant first ([hi0, lo0, hi1, lo1, ...]) so half-wise
    // lexicographic order equals limb-wise canonical-u64 order.
    let mut v: Vec<[Target; 8]> = values
        .into_iter()
        .map(|d| {
            let mut halves = [d[0]; 8];
            for j in 0..4 {
                let (lo, hi) = split_canonical_u32_halves(b, d[j]);
                halves[2 * j] = hi;
                halves[2 * j + 1] = lo;
            }
            halves
        })
        .collect();

    for round in 0..n {
        let mut i = round % 2;
        while i + 1 < n {
            let lhs = v[i];
            let rhs = v[i + 1];
            let lhs_lt = halves8_lt(b, &lhs, &rhs);
            for j in 0..8 {
                v[i][j] = b.select(lhs_lt, lhs[j], rhs[j]);
                v[i + 1][j] = b.select(lhs_lt, rhs[j], lhs[j]);
            }
            i += 2;
        }
    }

    // Egress: recombine each digest's halves back into 64-bit limbs.
    let two_pow_32 = F::from_canonical_u64(1 << 32);
    v.into_iter()
        .map(|halves| {
            core::array::from_fn(|j| b.mul_const_add(two_pow_32, halves[2 * j], halves[2 * j + 1]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{wormhole_private_batch_circuit_config, C, D, F};
    use alloc::vec;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    /// Gates added by `sort_digests4` over `n` virtual digests under the
    /// production private-batch circuit config.
    fn sort_gate_cost(n: usize) -> usize {
        let mut b = CircuitBuilder::<F, D>::new(wormhole_private_batch_circuit_config());
        let values: Vec<[Target; 4]> = (0..n)
            .map(|_| core::array::from_fn(|_| b.add_virtual_target()))
            .collect();
        let before = b.num_gates();
        let _ = sort_digests4(&mut b, values);
        b.num_gates() - before
    }

    /// The sorting network's cost is quadratic in the batch size (`n_leaf`
    /// is operator-configurable up to `MAX_PROOF_COUNT = 64`), so its
    /// per-comparator cost must stay hoisted: limbs are split once at
    /// ingress, not re-split inside every comparator (which costs ~3x more
    /// range-check work and at n=64 enough gates to risk crossing a
    /// power-of-two degree boundary). Budgets are the measured cost of the
    /// hoisted implementation plus ~15% headroom; the naive re-splitting
    /// implementation exceeds them by ~60% and must fail.
    #[test]
    fn sort_digests4_gate_cost_stays_hoisted() {
        for (n, budget) in [(8usize, 900), (64usize, 57_000)] {
            let cost = sort_gate_cost(n);
            std::println!("sort_digests4 n={n}: {cost} gates (budget {budget})");
            assert!(
                cost <= budget,
                "n={n}: {cost} gates exceeds budget {budget}"
            );
        }
    }

    /// Prove a circuit that sorts a fixed set of digests and exposes the
    /// result as public inputs; the proved order must equal the native
    /// `[u64; 4]` sort the spec's `digestLt` is pinned against. Exercises
    /// duplicate digests, shared prefixes that differ only in the last limb,
    /// half-limb boundary values (2^32 - 1 vs 2^32), and the canonical
    /// maximum p - 1.
    #[test]
    fn sort_digests4_proves_native_sort_order() {
        const P: u64 = 0xFFFF_FFFF_0000_0001;
        let inputs: Vec<[u64; 4]> = vec![
            [7, 7, 7, 7],
            [0, 0, 0, 0],
            [P - 1, P - 1, P - 1, P - 1],
            [7, 7, 7, 6],
            [0, (1 << 32) - 1, 0, 0],
            [0, 1 << 32, 0, 0],
            [7, 7, 7, 7], // duplicate
            [1, 0, 0, P - 1],
        ];

        // Not the production (zk) config: blinding needs plonky2's `rand`
        // feature, which this crate doesn't enable, and sort order is
        // independent of blinding.
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let targets: Vec<[Target; 4]> = (0..inputs.len())
            .map(|_| core::array::from_fn(|_| b.add_virtual_target()))
            .collect();
        for sorted in sort_digests4(&mut b, targets.clone()) {
            for t in sorted {
                b.register_public_input(t);
            }
        }
        let data = b.build::<C>();

        let mut pw = PartialWitness::new();
        for (digest_t, digest_v) in targets.iter().zip(&inputs) {
            for (t, v) in digest_t.iter().zip(digest_v) {
                pw.set_target(*t, F::from_canonical_u64(*v)).unwrap();
            }
        }
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();

        let mut expected = inputs;
        expected.sort();
        let proved: Vec<[u64; 4]> = proof
            .public_inputs
            .chunks_exact(4)
            .map(|c| core::array::from_fn(|i| c[i].to_canonical_u64()))
            .collect();
        assert_eq!(proved, expected, "in-circuit sort must match native sort");
    }
}
