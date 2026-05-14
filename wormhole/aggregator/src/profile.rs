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
    use crate::layer0::circuit::circuit_logic::Layer0AggregationCircuit;
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
                wormhole_aggregator_circuit_config(),
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
            wormhole_aggregator_circuit_config(),
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
                wormhole_aggregator_circuit_config(),
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
                wormhole_aggregator_circuit_config(),
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

    /// Compare two L0 approaches with REAL wormhole leaf proofs:
    /// 1. Direct ZK: 16 leaves → 1 ZK L0
    /// 2. NonZK + Wrap: 16 leaves → 1 non-ZK → 1 ZK wrapper
    ///
    /// ```bash
    /// cargo test -p qp-wormhole-aggregator --features profile --release compare_zk_approaches_real -- --nocapture --ignored
    /// ```
    #[test]
    #[ignore]
    fn compare_zk_approaches_real() {
        use plonky2::field::types::Field;
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};
        use plonky2::plonk::proof::ProofWithPublicInputs;
        use std::time::Instant;
        use test_helpers::TestInputs;
        use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
        use wormhole_circuit::inputs::CircuitInputs;
        use wormhole_prover::fill_witness;

        println!("\n╔════════════════════════════════════════════════════════════════════╗");
        println!("║  COMPARING ZK APPROACHES (REAL WORMHOLE PROOFS)                    ║");
        println!("║  Option A: 16 leaves → 1 ZK L0                                     ║");
        println!("║  Option B: 16 leaves → 1 non-ZK → 1 ZK wrap                        ║");
        println!("╚════════════════════════════════════════════════════════════════════╝\n");

        let num_leaves = 16;

        // Build the real wormhole leaf circuit
        println!("Building real wormhole leaf circuit...");
        let build_start = Instant::now();
        let leaf_circuit = WormholeCircuit::new(CircuitConfig::standard_recursion_config());
        let leaf_targets = leaf_circuit.targets();
        let leaf_data = leaf_circuit.build_circuit();
        let leaf_build_time = build_start.elapsed();

        println!("  Build time: {:.2}s", leaf_build_time.as_secs_f64());
        println!("  Degree bits: {}", leaf_data.common.degree_bits());
        println!("  Num PIs: {}\n", leaf_data.common.num_public_inputs);

        // Generate real leaf proofs
        println!("Generating {} real wormhole leaf proofs...", num_leaves);
        let start = Instant::now();
        let leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..num_leaves)
            .map(|_| {
                let inputs = CircuitInputs::test_inputs_0();
                let mut pw = PartialWitness::new();
                fill_witness(&mut pw, &inputs, &leaf_targets).expect("fill witness failed");
                leaf_data.prove(pw).expect("prove failed")
            })
            .collect();
        let leaf_gen_time = start.elapsed();
        println!(
            "Generated {} leaf proofs in {:.2}s ({:.0}ms/proof)\n",
            num_leaves,
            leaf_gen_time.as_secs_f64(),
            leaf_gen_time.as_secs_f64() * 1000.0 / num_leaves as f64
        );

        // =========================================================================
        // OPTION A: Direct ZK (16 leaves → 1 ZK L0)
        // =========================================================================
        println!("┌─────────────────────────────────────────────────────────────────────┐");
        println!("│  OPTION A: 16 leaves → 1 ZK L0 (current approach)                  │");
        println!("└─────────────────────────────────────────────────────────────────────┘\n");

        let zk_config = CircuitConfig::standard_recursion_polyfri_zk_config();

        println!("Building ZK L0 circuit...");
        let build_start = Instant::now();
        let zk_l0_circuit =
            Layer0AggregationCircuit::new(zk_config.clone(), leaf_data.common.clone(), num_leaves);
        let zk_l0_targets = zk_l0_circuit.targets();
        let zk_l0_data = zk_l0_circuit.build_circuit();
        let zk_build_time = build_start.elapsed();

        println!("  Build time: {:.2}s", zk_build_time.as_secs_f64());
        println!("  Degree bits: {}", zk_l0_data.common.degree_bits());
        println!("  Num PIs: {}\n", zk_l0_data.common.num_public_inputs);

        println!("Proving ZK L0...");
        let prove_start = Instant::now();
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(&zk_l0_targets.leaf_verifier_data, &leaf_data.verifier_only)
            .unwrap();
        for (pt, proof) in zk_l0_targets.leaf_proofs.iter().zip(leaf_proofs.iter()) {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }
        for pre_image in &zk_l0_targets.dummy_nullifier_pre_images {
            for (i, t) in pre_image.iter().enumerate() {
                pw.set_target(*t, F::from_canonical_u64(i as u64)).unwrap();
            }
        }
        let _zk_l0_proof = zk_l0_data.prove(pw).unwrap();
        let zk_prove_time = prove_start.elapsed();

        println!("  Prove time: {:.2}s\n", zk_prove_time.as_secs_f64());

        let option_a_total = zk_prove_time.as_secs_f64();

        // =========================================================================
        // OPTION B: Non-ZK + Wrap (16 leaves → 1 non-ZK → 1 ZK wrap)
        // =========================================================================
        println!("┌─────────────────────────────────────────────────────────────────────┐");
        println!("│  OPTION B: 16 leaves → 1 non-ZK → 1 ZK wrap                        │");
        println!("└─────────────────────────────────────────────────────────────────────┘\n");

        let nonzk_config = CircuitConfig::standard_recursion_config();

        // Step 1: Build non-ZK L0
        println!("Building non-ZK L0 circuit...");
        let build_start = Instant::now();
        let nonzk_l0_circuit = Layer0AggregationCircuit::new(
            nonzk_config.clone(),
            leaf_data.common.clone(),
            num_leaves,
        );
        let nonzk_l0_targets = nonzk_l0_circuit.targets();
        let nonzk_l0_data = nonzk_l0_circuit.build_circuit();
        let nonzk_build_time = build_start.elapsed();

        println!("  Build time: {:.2}s", nonzk_build_time.as_secs_f64());
        println!("  Degree bits: {}", nonzk_l0_data.common.degree_bits());
        println!("  Num PIs: {}\n", nonzk_l0_data.common.num_public_inputs);

        // Prove non-ZK L0
        println!("Proving non-ZK L0...");
        let prove_start = Instant::now();
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(
            &nonzk_l0_targets.leaf_verifier_data,
            &leaf_data.verifier_only,
        )
        .unwrap();
        for (pt, proof) in nonzk_l0_targets.leaf_proofs.iter().zip(leaf_proofs.iter()) {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }
        for pre_image in &nonzk_l0_targets.dummy_nullifier_pre_images {
            for (i, t) in pre_image.iter().enumerate() {
                pw.set_target(*t, F::from_canonical_u64(i as u64)).unwrap();
            }
        }
        let nonzk_l0_proof = nonzk_l0_data.prove(pw).unwrap();
        let nonzk_prove_time = prove_start.elapsed();

        println!("  Prove time: {:.2}s\n", nonzk_prove_time.as_secs_f64());

        // Step 2: Build ZK wrapper (verifies 1 non-ZK proof)
        println!("Building ZK wrapper circuit...");
        let build_start = Instant::now();

        // Use the ZkWrapperCircuit module instead of inline circuit building
        use crate::zk_wrapper::ZkWrapperCircuit;
        let wrapper_circuit = ZkWrapperCircuit::new(zk_config, nonzk_l0_data.common.clone());
        let wrapper_targets = wrapper_circuit.targets();
        let wrapper_data = wrapper_circuit.build_circuit();
        let wrapper_build_time = build_start.elapsed();

        println!("  Build time: {:.2}s", wrapper_build_time.as_secs_f64());
        println!("  Degree bits: {}", wrapper_data.common.degree_bits());
        println!("  Num PIs: {}\n", wrapper_data.common.num_public_inputs);

        // Prove ZK wrapper
        println!("Proving ZK wrapper...");
        let prove_start = Instant::now();
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(
            &wrapper_targets.inner_verifier_data,
            &nonzk_l0_data.verifier_only,
        )
        .unwrap();
        pw.set_proof_with_pis_target(&wrapper_targets.inner_proof, &nonzk_l0_proof)
            .unwrap();
        let _wrapper_proof = wrapper_data.prove(pw).unwrap();
        let wrapper_prove_time = prove_start.elapsed();

        println!("  Prove time: {:.2}s\n", wrapper_prove_time.as_secs_f64());

        let option_b_total = nonzk_prove_time.as_secs_f64() + wrapper_prove_time.as_secs_f64();

        // =========================================================================
        // SUMMARY
        // =========================================================================
        println!("╔════════════════════════════════════════════════════════════════════╗");
        println!("║  SUMMARY (proving times only, excluding one-time circuit builds)   ║");
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                    ║");
        println!(
            "║  Leaf proofs: {} × {:.0}ms = {:.2}s                                ║",
            num_leaves,
            leaf_gen_time.as_secs_f64() * 1000.0 / num_leaves as f64,
            leaf_gen_time.as_secs_f64()
        );
        println!("║                                                                    ║");
        println!("║  OPTION A: 16 leaves → 1 ZK L0                                     ║");
        println!(
            "║    ZK L0 prove:    {:>8.2}s                                       ║",
            zk_prove_time.as_secs_f64()
        );
        println!(
            "║    TOTAL PROVE:    {:>8.2}s                                       ║",
            option_a_total
        );
        println!("║                                                                    ║");
        println!("║  OPTION B: 16 leaves → 1 non-ZK → 1 ZK wrap                        ║");
        println!(
            "║    Non-ZK prove:   {:>8.2}s                                       ║",
            nonzk_prove_time.as_secs_f64()
        );
        println!(
            "║    Wrapper prove:  {:>8.2}s                                       ║",
            wrapper_prove_time.as_secs_f64()
        );
        println!(
            "║    TOTAL PROVE:    {:>8.2}s                                       ║",
            option_b_total
        );
        println!("║                                                                    ║");
        println!(
            "║  SPEEDUP: {:.2}x (Option B vs Option A)                            ║",
            option_a_total / option_b_total
        );
        println!("║                                                                    ║");
        println!("║  END-TO-END (leaf gen + aggregation):                              ║");
        println!(
            "║    Option A: {:.2}s + {:.2}s = {:.2}s                              ║",
            leaf_gen_time.as_secs_f64(),
            option_a_total,
            leaf_gen_time.as_secs_f64() + option_a_total
        );
        println!(
            "║    Option B: {:.2}s + {:.2}s = {:.2}s                              ║",
            leaf_gen_time.as_secs_f64(),
            option_b_total,
            leaf_gen_time.as_secs_f64() + option_b_total
        );
        println!("║                                                                    ║");
        println!("╚════════════════════════════════════════════════════════════════════╝\n");
    }
}
