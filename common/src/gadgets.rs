use alloc::vec::Vec;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

/// Compares a constant integer `left` with a variable `right` in a circuit, and returns whether
/// or not `left < right`.
///
/// # Returns
/// - `BoolTarget`: True if `left < right`, false otherwise.
pub fn is_const_less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: usize,
    right: Target,
    n_log: usize,
) -> BoolTarget {
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
pub fn xor<F: RichField + Extendable<D>, const D: usize>(
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

#[inline]
pub fn range32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: Target,
) {
    // Constrain x < 2^32
    b.range_check(x, 32);
}

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

/// Count unique 4x32-bit keys (big-endian limbs) among N leaves:
/// For each i, flag[i] = 1 if key[i] != key[j] for all j<i, else 0.
/// Returns sum(flag) as a Target.
pub fn count_unique_4x32_keys<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    keys: &[[Target; 4]],
) -> Target {
    let n = keys.len();
    let one = b.one();
    let mut first_flags: Vec<Target> = Vec::with_capacity(n);

    for i in 0..n {
        // seen_any = OR_{j<i} (keys[i] == keys[j])
        let mut seen_any = BoolTarget::new_unsafe(b.zero());
        for j in 0..i {
            let eq = bytes_digest_eq(b, keys[i], keys[j]); // BoolTarget
            seen_any = b.or(seen_any, eq);
        }
        // first_i = 1 - seen_any
        let first_i = b.sub(one, seen_any.target);
        first_flags.push(first_i);
    }

    b.add_many(&first_flags)
}

/// 128-bit add in   2^32 using *bit-split* to derive the carry bit.
/// Inputs a,c are 4x32-bit limbs big-endian (limb0 = most significant).
/// Returns (sum_limbs, top_carry_target).
/// Big-endian 128-bit add in base 2^32.
/// `a[0]`/`c[0]` = most significant 32-bit limb, `a[3]`/`c[3]` = least significant.
/// Returns (sum_limbs_be, top_carry), where top_carry is the carry out of the MSB.
///
/// This matches a packing like (what we have in felt utils):
///   value = a[0]<<96 | a[1]<<64 | a[2]<<32 | a[3]
pub fn add_u128_base2_32_split<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    a: [Target; 4],
    c: [Target; 4],
) -> ([Target; 4], Target) {
    // Ensure inputs are 32-bit limbs.
    for limb in a.iter().chain(c.iter()) {
        b.range_check(*limb, 32);
    }

    // Precompute 2^j constants once (0..31).
    let pow2: Vec<Target> = (0..32)
        .map(|j| b.constant(F::from_canonical_u64(1u64 << j)))
        .collect();

    let mut sum = [b.zero(); 4];
    // Carry propagates from LSB (index 3) up to MSB (index 0).
    let mut carry_prev = b.zero();

    // Process limbs in big-endian order: 3 (LSB), 2, 1, 0 (MSB).
    for k in (0..4).rev() {
        // s_raw ∈ [0, 2^33 - 1]
        let s1 = b.add(a[k], c[k]);
        let s_raw = b.add(s1, carry_prev);

        // Split into 33 little-endian bits: low 32 bits = sum_i, bit 32 = carry.
        let bits: Vec<BoolTarget> = b.split_le(s_raw, 33);

        // Reconstruct the 32-bit sum_i.
        let mut sum_i = b.zero();
        for j in 0..32 {
            let term = b.mul(bits[j].target, pow2[j]);
            sum_i = b.add(sum_i, term);
        }
        b.range_check(sum_i, 32);

        sum[k] = sum_i;
        carry_prev = bits[32].target; // carry to the next more-significant limb
    }

    // carry_prev is the carry out of the MSB.
    (sum, carry_prev)
}
