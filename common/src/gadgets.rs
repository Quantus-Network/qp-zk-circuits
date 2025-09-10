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
