#![cfg(test)]

use plonky2::plonk::circuit_data::CircuitConfig;
use zk_circuits_common::circuit::wormhole_leaf_circuit_config;

pub mod aggregator_tests;

/// Returns the circuit config for leaf proofs (non-ZK).
/// Leaf proofs are only verified by the aggregator, not on-chain.
pub fn circuit_config() -> CircuitConfig {
    wormhole_leaf_circuit_config()
}
