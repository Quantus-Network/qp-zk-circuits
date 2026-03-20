//! Circuit profiling utilities for analyzing gate counts and circuit complexity.
//!
//! This module is only available when the `profile` feature is enabled.
//!
//! # Usage
//!
//! ```bash
//! RUST_LOG=debug cargo test -p qp-wormhole-circuit --features profile --release profile_ -- --nocapture
//! ```
//!
//! The `RUST_LOG=debug` environment variable is required to see per-gate-type instance counts.

use plonky2::plonk::circuit_data::CommonCircuitData;
use zk_circuits_common::circuit::{D, F};

/// Prints overall circuit metrics from CommonCircuitData.
pub fn print_circuit_metrics(common: &CommonCircuitData<F, D>) {
    println!("\n=== Final Circuit Metrics ===");
    println!(
        "Degree bits: {} (circuit size: {})",
        common.degree_bits(),
        common.degree()
    );
    println!("Total gate constraints: {}", common.num_gate_constraints);
    println!("Unique gate types: {}", common.gates.len());
    println!("Number of public inputs: {}", common.num_public_inputs);
    println!("Number of routed wires: {}", common.config.num_routed_wires);
    println!("Number of wires: {}", common.config.num_wires);
    println!("Number of constants: {}", common.num_constants);
}

/// Helper struct for tracking gate counts during circuit building.
pub struct GateProfiler {
    last_count: usize,
    fragment_counts: Vec<(String, usize)>,
}

impl GateProfiler {
    /// Create a new gate profiler.
    pub fn new() -> Self {
        Self {
            last_count: 0,
            fragment_counts: Vec::new(),
        }
    }

    /// Record the gate count after a fragment, computing the delta from the last checkpoint.
    pub fn checkpoint(&mut self, name: &str, current_gates: usize) {
        let delta = current_gates - self.last_count;
        self.fragment_counts.push((name.to_string(), delta));
        self.last_count = current_gates;
        println!("After {}: {} gates (+{})", name, current_gates, delta);
    }

    /// Print a summary of all fragments.
    pub fn print_summary(&self) {
        println!("\n=== Circuit Fragment Summary ===");
        let total: usize = self.fragment_counts.iter().map(|(_, c)| c).sum();

        for (name, count) in &self.fragment_counts {
            let percentage = (*count as f64 / total as f64) * 100.0;
            println!("{}: {} gates ({:.1}%)", name, count, percentage);
        }
        println!("Total gates from fragments: {}", total);
    }
}

impl Default for GateProfiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::circuit_logic::WormholeCircuit;
    use plonky2::plonk::circuit_data::CircuitConfig;

    /// Profile the wormhole circuit in both ZK and non-ZK configurations.
    ///
    /// Run with:
    /// ```bash
    /// RUST_LOG=debug cargo test -p qp-wormhole-circuit --features profile --release profile_ -- --nocapture
    /// ```
    #[test]
    fn profile_wormhole_circuit() {
        // Initialize logger to see debug! output from print_gate_counts
        let _ = env_logger::builder().is_test(true).try_init();

        // =====================================================================
        // ZK Configuration
        // =====================================================================
        println!("\n========================================");
        println!("   WORMHOLE CIRCUIT PROFILE (ZK)");
        println!("========================================\n");

        let config = wormhole_circuit_config();
        let circuit = WormholeCircuit::new(config);
        let data = circuit.build_circuit_profiled();
        print_circuit_metrics(&data.common);

        // =====================================================================
        // Non-ZK Configuration
        // =====================================================================
        println!("\n========================================");
        println!("   WORMHOLE CIRCUIT PROFILE (NO ZK)");
        println!("========================================\n");

        let config = CircuitConfig::standard_recursion_config();
        let circuit = WormholeCircuit::new(config);
        let data = circuit.build_circuit_profiled();
        print_circuit_metrics(&data.common);

        println!("\n========================================\n");
    }
}
