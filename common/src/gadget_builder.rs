//! The builder surface the wormhole wrapper logic is written against.
//!
//! [`GadgetBuilder`] names exactly the `CircuitBuilder` gadgets the aggregation wrappers
//! use. `CircuitBuilder` implements it by forwarding, so production circuits are unchanged;
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
    fn one(&mut self) -> Target;
    fn zero(&mut self) -> Target;
    fn constant(&mut self, c: F) -> Target;
    fn _false(&mut self) -> BoolTarget;
    fn add_virtual_bool_target_safe(&mut self) -> BoolTarget;
    fn not(&mut self, b: BoolTarget) -> BoolTarget;
    fn and(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget;
    fn or(&mut self, b1: BoolTarget, b2: BoolTarget) -> BoolTarget;
    fn select(&mut self, b: BoolTarget, x: Target, y: Target) -> Target;
    fn is_equal(&mut self, x: Target, y: Target) -> BoolTarget;
    fn add(&mut self, x: Target, y: Target) -> Target;
    fn sub(&mut self, x: Target, y: Target) -> Target;
    fn mul(&mut self, x: Target, y: Target) -> Target;
    fn connect(&mut self, x: Target, y: Target);
    fn range_check(&mut self, x: Target, n_log: usize);
    fn register_public_inputs(&mut self, targets: &[Target]);
    /// `CircuitBuilder::hash_n_to_hash_no_pad_p2::<Poseidon2Hash>`.
    fn poseidon2_hash_no_pad(&mut self, inputs: Vec<Target>) -> HashOutTarget;
}

impl<F, const D: usize> GadgetBuilder<F, D> for CircuitBuilder<F, D>
where
    F: RichField + Extendable<D>,
    Poseidon2Hash: AlgebraicHasher<F>,
{
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
    fn connect(&mut self, x: Target, y: Target) {
        CircuitBuilder::connect(self, x, y)
    }
    fn range_check(&mut self, x: Target, n_log: usize) {
        CircuitBuilder::range_check(self, x, n_log)
    }
    fn register_public_inputs(&mut self, targets: &[Target]) {
        CircuitBuilder::register_public_inputs(self, targets)
    }
    fn poseidon2_hash_no_pad(&mut self, inputs: Vec<Target>) -> HashOutTarget {
        self.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inputs)
    }
}
