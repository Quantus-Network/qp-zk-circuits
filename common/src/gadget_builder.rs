//! The builder surface the wormhole circuits are written against.
//!
//! [`GadgetBuilder`] names exactly the `CircuitBuilder` gadgets the leaf circuit and the
//! aggregation wrappers use. `CircuitBuilder` implements it by forwarding, so production circuits are unchanged;
//! the `formal-export` feature adds a second implementation ([`crate::formal_trace::TracingBuilder`])
//! that records every call for the constraint exporter in `qp-plonky2/constraint-exporter`.

use alloc::vec::Vec;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon2::Poseidon2Hash,
    },
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

pub trait GadgetBuilder<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_target(&mut self) -> Target;
    fn add_virtual_targets(&mut self, n: usize) -> Vec<Target>;
    fn add_virtual_public_input(&mut self) -> Target;
    fn add_virtual_hash(&mut self) -> HashOutTarget;
    fn add_virtual_hash_public_input(&mut self) -> HashOutTarget;
    fn one(&mut self) -> Target;
    fn zero(&mut self) -> Target;
    fn constant(&mut self, c: F) -> Target;
    fn _false(&mut self) -> BoolTarget;
    fn _true(&mut self) -> BoolTarget;
    fn constant_bool(&mut self, b: bool) -> BoolTarget;
    fn add_virtual_bool_target_safe(&mut self) -> BoolTarget;
    fn not(&mut self, b: BoolTarget) -> BoolTarget;
    fn and(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget;
    fn or(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget;
    fn select(&mut self, b: BoolTarget, x: Target, y: Target) -> Target;
    fn is_equal(&mut self, x: Target, y: Target) -> BoolTarget;
    fn add(&mut self, x: Target, y: Target) -> Target;
    fn sub(&mut self, x: Target, y: Target) -> Target;
    fn mul(&mut self, x: Target, y: Target) -> Target;
    /// `CircuitBuilder::mul_const`, i.e. `mul(constant(c), x)`.
    fn mul_const(&mut self, c: F, x: Target) -> Target;
    fn connect(&mut self, x: Target, y: Target);
    fn connect_hashes(&mut self, x: HashOutTarget, y: HashOutTarget);
    fn range_check(&mut self, x: Target, n_log: usize);
    /// `CircuitBuilder::split_le`: the `num_bits` little-endian bits of `x` (range-checking it).
    fn split_le(&mut self, x: Target, num_bits: usize) -> Vec<BoolTarget>;
    /// `CircuitBuilder::split_low_high`. Not modeled by the constraint exporter; only the
    /// 64-bit comparison path uses it, which no traced circuit takes.
    fn split_low_high(&mut self, x: Target, n_log: usize, num_bits: usize) -> (Target, Target);
    fn register_public_input(&mut self, target: Target);
    fn register_public_inputs(&mut self, targets: &[Target]);
    /// `CircuitBuilder::hash_n_to_hash_no_pad_p2::<Poseidon2Hash>`.
    fn poseidon2_hash_no_pad(&mut self, inputs: Vec<Target>) -> HashOutTarget;
}

impl<F, const D: usize> GadgetBuilder<F, D> for CircuitBuilder<F, D>
where
    F: RichField + Extendable<D>,
    Poseidon2Hash: AlgebraicHasher<F>,
{
    fn add_virtual_target(&mut self) -> Target {
        CircuitBuilder::add_virtual_target(self)
    }
    fn add_virtual_targets(&mut self, n: usize) -> Vec<Target> {
        CircuitBuilder::add_virtual_targets(self, n)
    }
    fn add_virtual_public_input(&mut self) -> Target {
        CircuitBuilder::add_virtual_public_input(self)
    }
    fn add_virtual_hash(&mut self) -> HashOutTarget {
        CircuitBuilder::add_virtual_hash(self)
    }
    fn add_virtual_hash_public_input(&mut self) -> HashOutTarget {
        CircuitBuilder::add_virtual_hash_public_input(self)
    }
    fn one(&mut self) -> Target {
        CircuitBuilder::one(self)
    }
    fn zero(&mut self) -> Target {
        CircuitBuilder::zero(self)
    }
    fn constant(&mut self, c: F) -> Target {
        CircuitBuilder::constant(self, c)
    }
    fn _false(&mut self) -> BoolTarget {
        CircuitBuilder::_false(self)
    }
    fn _true(&mut self) -> BoolTarget {
        CircuitBuilder::_true(self)
    }
    fn constant_bool(&mut self, b: bool) -> BoolTarget {
        CircuitBuilder::constant_bool(self, b)
    }
    fn add_virtual_bool_target_safe(&mut self) -> BoolTarget {
        CircuitBuilder::add_virtual_bool_target_safe(self)
    }
    fn not(&mut self, b: BoolTarget) -> BoolTarget {
        CircuitBuilder::not(self, b)
    }
    fn and(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget {
        CircuitBuilder::and(self, b1, b2)
    }
    fn or(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget {
        CircuitBuilder::or(self, b1, b2)
    }
    fn select(&mut self, b: BoolTarget, x: Target, y: Target) -> Target {
        CircuitBuilder::select(self, b, x, y)
    }
    fn is_equal(&mut self, x: Target, y: Target) -> BoolTarget {
        CircuitBuilder::is_equal(self, x, y)
    }
    fn add(&mut self, x: Target, y: Target) -> Target {
        CircuitBuilder::add(self, x, y)
    }
    fn sub(&mut self, x: Target, y: Target) -> Target {
        CircuitBuilder::sub(self, x, y)
    }
    fn mul(&mut self, x: Target, y: Target) -> Target {
        CircuitBuilder::mul(self, x, y)
    }
    fn mul_const(&mut self, c: F, x: Target) -> Target {
        CircuitBuilder::mul_const(self, c, x)
    }
    fn connect(&mut self, x: Target, y: Target) {
        CircuitBuilder::connect(self, x, y)
    }
    fn connect_hashes(&mut self, x: HashOutTarget, y: HashOutTarget) {
        CircuitBuilder::connect_hashes(self, x, y)
    }
    fn range_check(&mut self, x: Target, n_log: usize) {
        CircuitBuilder::range_check(self, x, n_log)
    }
    fn split_le(&mut self, x: Target, num_bits: usize) -> Vec<BoolTarget> {
        CircuitBuilder::split_le(self, x, num_bits)
    }
    fn split_low_high(&mut self, x: Target, n_log: usize, num_bits: usize) -> (Target, Target) {
        CircuitBuilder::split_low_high(self, x, n_log, num_bits)
    }
    fn register_public_input(&mut self, target: Target) {
        CircuitBuilder::register_public_input(self, target)
    }
    fn register_public_inputs(&mut self, targets: &[Target]) {
        CircuitBuilder::register_public_inputs(self, targets)
    }
    fn poseidon2_hash_no_pad(&mut self, inputs: Vec<Target>) -> HashOutTarget {
        self.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inputs)
    }
}
