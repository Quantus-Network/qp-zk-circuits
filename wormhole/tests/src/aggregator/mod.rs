#![cfg(test)]

use plonky2::plonk::circuit_data::CircuitConfig;
pub mod aggregator_tests;

fn circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config()
}
