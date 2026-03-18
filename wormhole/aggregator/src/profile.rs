//! Circuit profiling utilities for analyzing gate counts and circuit complexity
//! of the aggregator circuits (layer0 and layer1).
//!
//! This module is only available when the `profile` feature is enabled.
//!
//! # Usage
//!
//! ```bash
//! # Profile layer0 aggregation circuit (with gate instance counts)
//! RUST_LOG=debug cargo test -p qp-wormhole-aggregator --features profile --release profile_layer0 -- --nocapture
//!
//! # Profile layer1 aggregation circuit (with gate instance counts)
//! RUST_LOG=debug cargo test -p qp-wormhole-aggregator --features profile --release profile_layer1 -- --nocapture
//!
//! # Profile both
//! RUST_LOG=debug cargo test -p qp-wormhole-aggregator --features profile --release profile_ -- --nocapture
//! ```
//!
//! The `RUST_LOG=debug` environment variable is required to see per-gate-type instance counts.

use plonky2::plonk::circuit_data::CommonCircuitData;
use zk_circuits_common::circuit::{D, F};

/// Prints overall circuit metrics from CommonCircuitData.
pub fn print_circuit_metrics(label: &str, common: &CommonCircuitData<F, D>) {
    println!("\n=== {} Circuit Metrics ===", label);
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

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    };
    use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN;
    use zk_circuits_common::circuit::C;

    use crate::layer0::circuit::circuit_logic::Layer0AggregationCircuit;
    use crate::layer1::circuit::circuit_logic::Layer1AggregationCircuit;

    /// Build a minimal fake leaf circuit that matches the Wormhole leaf PI layout.
    /// Used to get CommonCircuitData for layer0 circuit construction.
    fn build_fake_leaf_circuit() -> CircuitData<F, C, D> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis_vec = builder.add_virtual_targets(LEAF_PI_LEN);

        // Minimal constraints to mimic real leaf circuit
        builder.range_check(pis_vec[1], 32); // output_amount_1
        builder.range_check(pis_vec[2], 32); // output_amount_2
        builder.range_check(pis_vec[3], 32); // volume_fee_bps

        builder.register_public_inputs(&pis_vec);

        builder.build::<C>()
    }

    #[test]
    fn profile_layer0_circuit() {
        // Initialize logger to see debug! output from print_gate_counts
        let _ = env_logger::builder().is_test(true).try_init();

        println!("\n========================================");
        println!("   LAYER-0 AGGREGATION CIRCUIT PROFILE");
        println!("========================================\n");

        // Test with different numbers of leaf proofs
        for num_leaves in [2, 4, 8] {
            println!("\n--- Layer-0 with {} leaf proofs ---", num_leaves);

            // Build fake leaf circuit to get common data
            let leaf_data = build_fake_leaf_circuit();
            let leaf_common = leaf_data.common.clone();

            println!("Leaf circuit degree bits: {}", leaf_common.degree_bits());

            // Build layer-0 aggregation circuit
            let start = std::time::Instant::now();
            let l0_circuit = Layer0AggregationCircuit::new(
                CircuitConfig::standard_recursion_zk_config(),
                leaf_common,
                num_leaves,
            );

            // Print gate counts before building
            println!("Gates before build: {}", l0_circuit.num_gates());

            // Build with profiling (prints gate instance counts via debug!)
            let l0_data = l0_circuit.build_circuit_profiled();
            let build_time = start.elapsed();

            println!("Build time: {:?}", build_time);

            // Print metrics
            print_circuit_metrics(&format!("Layer-0 (n={})", num_leaves), &l0_data.common);

            // Calculate gates per leaf
            let total_gates = 1 << l0_data.common.degree_bits();
            let gates_per_leaf = total_gates / num_leaves;
            println!("\nGates per leaf proof: ~{}", gates_per_leaf);
        }

        println!("\n========================================\n");
    }

    #[test]
    fn profile_layer1_circuit() {
        // Initialize logger to see debug! output from print_gate_counts
        let _ = env_logger::builder().is_test(true).try_init();

        println!("\n========================================");
        println!("   LAYER-1 AGGREGATION CIRCUIT PROFILE");
        println!("========================================\n");

        // Fixed layer0 leaf count for layer1 testing
        let layer0_num_leaves = 4;

        // Build fake leaf circuit to get common data for layer0
        let leaf_data = build_fake_leaf_circuit();

        // Build layer-0 circuit to get its common data for layer1
        let l0_circuit = Layer0AggregationCircuit::new(
            CircuitConfig::standard_recursion_zk_config(),
            leaf_data.common.clone(),
            layer0_num_leaves,
        );
        let l0_data = l0_circuit.build_circuit();
        let l0_common = l0_data.common.clone();

        println!(
            "Layer-0 circuit (n={}) degree bits: {}",
            layer0_num_leaves,
            l0_common.degree_bits()
        );

        // Test with different numbers of layer-0 proofs
        for num_l0_proofs in [2, 4] {
            println!(
                "\n--- Layer-1 with {} layer-0 proofs (each with {} leaves) ---",
                num_l0_proofs, layer0_num_leaves
            );

            // Build layer-1 aggregation circuit
            let start = std::time::Instant::now();
            let l1_circuit = Layer1AggregationCircuit::new(
                CircuitConfig::standard_recursion_zk_config(),
                l0_common.clone(),
                num_l0_proofs,
                layer0_num_leaves,
            );

            // Print gate counts before building
            println!("Gates before build: {}", l1_circuit.num_gates());

            // Build with profiling (prints gate instance counts via debug!)
            let l1_data = l1_circuit.build_circuit_profiled();
            let build_time = start.elapsed();

            println!("Build time: {:?}", build_time);

            // Print metrics
            print_circuit_metrics(
                &format!(
                    "Layer-1 (n_l0={}, leaves={})",
                    num_l0_proofs, layer0_num_leaves
                ),
                &l1_data.common,
            );

            // Calculate effective leaf coverage
            let total_leaves = num_l0_proofs * layer0_num_leaves;
            let total_gates = 1 << l1_data.common.degree_bits();
            let gates_per_leaf = total_gates / total_leaves;
            println!(
                "\nTotal leaf proofs covered: {} ({} l0 proofs x {} leaves each)",
                total_leaves, num_l0_proofs, layer0_num_leaves
            );
            println!("Effective gates per original leaf: ~{}", gates_per_leaf);
        }

        println!("\n========================================\n");
    }

    #[test]
    fn profile_aggregation_scaling() {
        println!("\n========================================");
        println!("   AGGREGATION SCALING ANALYSIS");
        println!("========================================\n");

        let leaf_data = build_fake_leaf_circuit();
        let leaf_common = leaf_data.common.clone();

        println!("Leaf circuit:");
        println!("  Degree bits: {}", leaf_common.degree_bits());
        println!("  Public inputs: {}", leaf_common.num_public_inputs);

        println!("\n| Leaves | L0 Degree | L0 Gates | L0 PI Len |");
        println!("|--------|-----------|----------|-----------|");

        for num_leaves in [2, 4, 8, 16] {
            let l0_circuit = Layer0AggregationCircuit::new(
                CircuitConfig::standard_recursion_zk_config(),
                leaf_common.clone(),
                num_leaves,
            );
            let l0_data = l0_circuit.build_circuit();

            println!(
                "| {:>6} | {:>9} | {:>8} | {:>9} |",
                num_leaves,
                l0_data.common.degree_bits(),
                1 << l0_data.common.degree_bits(),
                l0_data.common.num_public_inputs
            );
        }

        println!("\n========================================\n");
    }
}
