#![cfg(test)]

use plonky2::plonk::circuit_data::CircuitConfig;
pub mod aggregator_tests;

fn circuit_config() -> CircuitConfig {
    // Use zk config to match CLI and production usage
    CircuitConfig::standard_recursion_zk_config()
}
