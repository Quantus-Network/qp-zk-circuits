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
