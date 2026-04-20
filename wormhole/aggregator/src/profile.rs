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
    use crate::layer0::circuit::{
        constants::TOTAL_NUM_LEAVES, InnerAggregationCircuit, OuterAggregationCircuit,
    };
    use crate::layer1::circuit::circuit_logic::Layer1AggregationCircuit;
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    };
    use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN;
    use zk_circuits_common::circuit::{wormhole_aggregator_circuit_config, C};

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
        println!("   SHIPPING LAYER-0 CIRCUIT PROFILE");
        println!("========================================\n");

        let leaf_data = build_fake_leaf_circuit();
        let leaf_common = leaf_data.common.clone();
        println!("Leaf circuit degree bits: {}", leaf_common.degree_bits());

        let start = std::time::Instant::now();
        let inner_circuit = InnerAggregationCircuit::new(leaf_common);
        println!("Inner gates before build: {}", inner_circuit.num_gates());
        let inner_data = inner_circuit.build_circuit_profiled();
        let inner_build_time = start.elapsed();
        println!("Inner build time: {:?}", inner_build_time);
        print_circuit_metrics("Layer-0 Inner (8 leaves)", &inner_data.common);
        println!(
            "\nInner gates per leaf proof: ~{}",
            (1 << inner_data.common.degree_bits()) / 8
        );

        let start = std::time::Instant::now();
        let outer_circuit = OuterAggregationCircuit::new(inner_data.common.clone());
        println!("Outer gates before build: {}", outer_circuit.num_gates());
        let outer_data = outer_circuit.build_circuit_profiled();
        let outer_build_time = start.elapsed();
        println!("Outer build time: {:?}", outer_build_time);
        print_circuit_metrics("Layer-0 Outer (2x8 wrapper)", &outer_data.common);
        println!(
            "\nOuter effective gates per leaf proof: ~{}",
            (1 << outer_data.common.degree_bits()) / TOTAL_NUM_LEAVES
        );

        println!("\n========================================\n");
    }

    #[test]
    fn profile_layer1_circuit() {
        // Initialize logger to see debug! output from print_gate_counts
        let _ = env_logger::builder().is_test(true).try_init();

        println!("\n========================================");
        println!("   LAYER-1 AGGREGATION CIRCUIT PROFILE");
        println!("========================================\n");

        let leaf_data = build_fake_leaf_circuit();
        let inner_data = InnerAggregationCircuit::new(leaf_data.common.clone()).build_circuit();
        let outer_data = OuterAggregationCircuit::new(inner_data.common.clone()).build_circuit();
        let layer0_common = outer_data.common.clone();

        println!(
            "Shipping layer-0 outer circuit (leaves={}) degree bits: {}",
            TOTAL_NUM_LEAVES,
            layer0_common.degree_bits()
        );

        // Test with different numbers of layer-0 proofs
        for num_l0_proofs in [2, 4] {
            println!(
                "\n--- Layer-1 with {} layer-0 proofs (each with {} leaves) ---",
                num_l0_proofs, TOTAL_NUM_LEAVES
            );

            // Build layer-1 aggregation circuit
            let start = std::time::Instant::now();
            let l1_circuit = Layer1AggregationCircuit::new(
                wormhole_aggregator_circuit_config(),
                layer0_common.clone(),
                num_l0_proofs,
                TOTAL_NUM_LEAVES,
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
                    num_l0_proofs, TOTAL_NUM_LEAVES
                ),
                &l1_data.common,
            );

            // Calculate effective leaf coverage
            let total_leaves = num_l0_proofs * TOTAL_NUM_LEAVES;
            let total_gates = 1 << l1_data.common.degree_bits();
            let gates_per_leaf = total_gates / total_leaves;
            println!(
                "\nTotal leaf proofs covered: {} ({} l0 proofs x {} leaves each)",
                total_leaves, num_l0_proofs, TOTAL_NUM_LEAVES
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
        let inner_data = InnerAggregationCircuit::new(leaf_data.common.clone()).build_circuit();
        let outer_data = OuterAggregationCircuit::new(inner_data.common.clone()).build_circuit();

        println!("\n| Stage | Degree | Gates | PI Len |");
        println!("|-------|--------|-------|--------|");
        println!(
            "| Leaf | {:>6} | {:>5} | {:>6} |",
            leaf_data.common.degree_bits(),
            1 << leaf_data.common.degree_bits(),
            leaf_data.common.num_public_inputs
        );
        println!(
            "| L0 Inner (8 leaves) | {:>6} | {:>5} | {:>6} |",
            inner_data.common.degree_bits(),
            1 << inner_data.common.degree_bits(),
            inner_data.common.num_public_inputs
        );
        println!(
            "| L0 Outer (16 leaves) | {:>6} | {:>5} | {:>6} |",
            outer_data.common.degree_bits(),
            1 << outer_data.common.degree_bits(),
            outer_data.common.num_public_inputs
        );

        for num_l0_proofs in [2, 4] {
            let l1_data = Layer1AggregationCircuit::new(
                wormhole_aggregator_circuit_config(),
                outer_data.common.clone(),
                num_l0_proofs,
                TOTAL_NUM_LEAVES,
            )
            .build_circuit();
            println!(
                "| L1 ({} x 16 leaves) | {:>6} | {:>5} | {:>6} |",
                num_l0_proofs,
                l1_data.common.degree_bits(),
                1 << l1_data.common.degree_bits(),
                l1_data.common.num_public_inputs
            );
        }

        println!("\n========================================\n");
    }
}
