//! Circuit profiling utilities for analyzing gate counts and circuit complexity
//! of the aggregator circuits (private_batch and public_batch).
//!
//! This module is only available when the `profile` feature is enabled.
//!
//! # Usage
//!
//! ```bash
//! # Profile private_batch aggregation circuit (with gate instance counts)
//! RUST_LOG=debug cargo test -p qp-wormhole-aggregator --features profile --release profile_private_batch -- --nocapture
//!
//! # Profile public_batch aggregation circuit (with gate instance counts)
//! RUST_LOG=debug cargo test -p qp-wormhole-aggregator --features profile --release profile_public_batch -- --nocapture
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
    use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;
    use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;
    use test_helpers::fake_leaf::build_fake_leaf_circuit_data_only;
    use zk_circuits_common::circuit::{
        wormhole_private_batch_circuit_config, wormhole_public_batch_circuit_config,
    };

    #[test]
    fn profile_private_batch_circuit() {
        // Initialize logger to see debug! output from print_gate_counts
        let _ = env_logger::builder().is_test(true).try_init();

        println!("\n========================================");
        println!("   LAYER-0 AGGREGATION CIRCUIT PROFILE");
        println!("========================================\n");

        // Test with different numbers of leaf proofs
        for num_leaves in [2, 4, 8] {
            println!("\n--- Private-batch with {} leaf proofs ---", num_leaves);

            // Build fake leaf circuit to get common data
            let leaf_data = build_fake_leaf_circuit_data_only();
            let leaf_common = leaf_data.common.clone();
            let leaf_verifier_only = leaf_data.verifier_only.clone();

            println!("Leaf circuit degree bits: {}", leaf_common.degree_bits());

            // Build private-batch aggregation circuit
            let start = std::time::Instant::now();
            let private_batch_circuit = PrivateBatchCircuit::new(
                wormhole_private_batch_circuit_config(),
                leaf_common,
                &leaf_verifier_only,
                num_leaves,
            );

            // Print gate counts before building
            println!("Gates before build: {}", private_batch_circuit.num_gates());

            // Build with profiling (prints gate instance counts via debug!)
            let private_batch_data = private_batch_circuit.build_circuit_profiled();
            let build_time = start.elapsed();

            println!("Build time: {:?}", build_time);

            // Print metrics
            print_circuit_metrics(&format!("Private-batch (n={})", num_leaves), &private_batch_data.common);

            // Calculate gates per leaf
            let total_gates = 1 << private_batch_data.common.degree_bits();
            let gates_per_leaf = total_gates / num_leaves;
            println!("\nGates per leaf proof: ~{}", gates_per_leaf);
        }

        println!("\n========================================\n");
    }

    #[test]
    fn profile_public_batch_circuit() {
        // Initialize logger to see debug! output from print_gate_counts
        let _ = env_logger::builder().is_test(true).try_init();

        println!("\n========================================");
        println!("   LAYER-1 AGGREGATION CIRCUIT PROFILE");
        println!("========================================\n");

        // Fixed private_batch leaf count for public_batch testing
        let private_batch_num_leaves = 4;

        // Build fake leaf circuit to get common data for private_batch
        let leaf_data = build_fake_leaf_circuit_data_only();

        // Build private-batch circuit to get its common data for public_batch
        let private_batch_circuit = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            leaf_data.common.clone(),
            &leaf_data.verifier_only,
            private_batch_num_leaves,
        );
        let private_batch_data = private_batch_circuit.build_circuit();
        let private_batch_common = private_batch_data.common.clone();
        let private_batch_verifier_only = private_batch_data.verifier_only.clone();

        println!(
            "Private-batch circuit (n={}) degree bits: {}",
            private_batch_num_leaves,
            private_batch_common.degree_bits()
        );

        // Test with different numbers of private-batch proofs
        for num_l0_proofs in [2, 4] {
            println!(
                "\n--- Public-batch with {} private-batch proofs (each with {} leaves) ---",
                num_l0_proofs, private_batch_num_leaves
            );

            // Build public-batch aggregation circuit
            let start = std::time::Instant::now();
            let public_batch_circuit = PublicBatchCircuit::new(
                wormhole_public_batch_circuit_config(),
                private_batch_common.clone(),
                &private_batch_verifier_only,
                num_l0_proofs,
                private_batch_num_leaves,
            );

            // Print gate counts before building
            println!("Gates before build: {}", public_batch_circuit.num_gates());

            // Build with profiling (prints gate instance counts via debug!)
            let public_batch_data = public_batch_circuit.build_circuit_profiled();
            let build_time = start.elapsed();

            println!("Build time: {:?}", build_time);

            // Print metrics
            print_circuit_metrics(
                &format!(
                    "Public-batch (n_l0={}, leaves={})",
                    num_l0_proofs, private_batch_num_leaves
                ),
                &public_batch_data.common,
            );

            // Calculate effective leaf coverage
            let total_leaves = num_l0_proofs * private_batch_num_leaves;
            let total_gates = 1 << public_batch_data.common.degree_bits();
            let gates_per_leaf = total_gates / total_leaves;
            println!(
                "\nTotal leaf proofs covered: {} ({} l0 proofs x {} leaves each)",
                total_leaves, num_l0_proofs, private_batch_num_leaves
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

        let leaf_data = build_fake_leaf_circuit_data_only();
        let leaf_common = leaf_data.common.clone();
        let leaf_verifier_only = leaf_data.verifier_only.clone();

        println!("Leaf circuit:");
        println!("  Degree bits: {}", leaf_common.degree_bits());
        println!("  Public inputs: {}", leaf_common.num_public_inputs);

        println!("\n| Leaves | private-batch Degree | private-batch Gates | private-batch PI Len |");
        println!("|--------|-----------|----------|-----------|");

        for num_leaves in [2, 4, 8, 16] {
            let private_batch_circuit = PrivateBatchCircuit::new(
                wormhole_private_batch_circuit_config(),
                leaf_common.clone(),
                &leaf_verifier_only,
                num_leaves,
            );
            let private_batch_data = private_batch_circuit.build_circuit();

            println!(
                "| {:>6} | {:>9} | {:>8} | {:>9} |",
                num_leaves,
                private_batch_data.common.degree_bits(),
                1 << private_batch_data.common.degree_bits(),
                private_batch_data.common.num_public_inputs
            );
        }

        println!("\n========================================\n");
    }
}
