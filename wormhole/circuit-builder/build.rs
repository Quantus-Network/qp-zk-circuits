//! Build script for qp-wormhole-circuit-builder.
//!
//! Generates circuit binaries to `wormhole/generated-bins/` for use by
//! benchmarks and tests in sibling crates.

use std::{env, path::Path, time::Instant};

fn main() {
    // Don't emit any rerun-if-changed directives - this forces the build script
    // to run on every build. Circuit generation is fast enough in release mode.

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let output_dir = Path::new(&manifest_dir).join("../generated-bins");

    // Only regenerate if the directory exists (i.e., this is a dev environment)
    // Skip if running in CI or publish verification where we don't need benches
    if !output_dir.exists() {
        return;
    }

    let num_leaf_proofs: usize = env::var("QP_NUM_LEAF_PROOFS")
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .expect("QP_NUM_LEAF_PROOFS must be a valid usize");

    println!(
        "cargo:warning=[qp-wormhole-circuit-builder] Generating circuit binaries (num_leaf_proofs={})...",
        num_leaf_proofs
    );

    let start = Instant::now();

    generate_bins(&output_dir, num_leaf_proofs);

    let elapsed = start.elapsed();
    println!(
        "cargo:warning=[qp-wormhole-circuit-builder] Circuit binaries generated in {:.2}s",
        elapsed.as_secs_f64()
    );
}

fn generate_bins(output_dir: &Path, num_leaf_proofs: usize) {
    use std::fs::{create_dir_all, write};

    create_dir_all(output_dir).expect("Failed to create output directory");

    // Generate leaf circuit
    println!("cargo:warning=  Building leaf circuit...");
    let config = zk_circuits_common::circuit::wormhole_leaf_circuit_config();
    let circuit = wormhole_circuit::circuit::circuit_logic::WormholeCircuit::new(config);
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();

    let gate_serializer = plonky2::util::serialization::DefaultGateSerializer;
    let generator_serializer = plonky2::util::serialization::DefaultGeneratorSerializer::<
        zk_circuits_common::circuit::C,
        { zk_circuits_common::circuit::D },
    > {
        _phantom: Default::default(),
    };

    // Generate dummy proof
    println!("cargo:warning=  Generating dummy proof...");
    let dummy_proof_bytes = wormhole_aggregator::generate_dummy_proof(&circuit_data, &targets)
        .expect("Failed to generate dummy proof");
    write(output_dir.join("dummy_proof.bin"), &dummy_proof_bytes)
        .expect("Failed to write dummy proof");

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // Serialize common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .expect("Failed to serialize common data");
    write(output_dir.join("common.bin"), common_bytes).expect("Failed to write common.bin");

    // Serialize verifier data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .expect("Failed to serialize verifier data");
    write(output_dir.join("verifier.bin"), verifier_only_bytes)
        .expect("Failed to write verifier.bin");

    // Serialize prover data
    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .expect("Failed to serialize prover data");
    write(output_dir.join("prover.bin"), prover_only_bytes).expect("Failed to write prover.bin");

    // Generate layer0 aggregation circuit
    println!("cargo:warning=  Building layer0 aggregation circuit...");
    wormhole_aggregator::layer0::circuit::build::generate_layer0_circuit_binaries(
        output_dir,
        num_leaf_proofs,
        true,
    )
    .expect("Failed to generate layer0 circuit binaries");

    // Save config
    let config = wormhole_aggregator::CircuitBinsConfig::new(num_leaf_proofs, None);
    config.save(output_dir).expect("Failed to save config");
}
