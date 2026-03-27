#![cfg(test)]

use plonky2::plonk::circuit_data::CircuitConfig;
use zk_circuits_common::circuit::wormhole_circuit_config;

pub mod aggregator_tests;

pub fn circuit_config() -> CircuitConfig {
    wormhole_circuit_config()
}
