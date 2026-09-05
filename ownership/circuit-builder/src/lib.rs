//! Ownership-circuit artifact generation.
//!
//! Intended to run on a trusted CI build host. No `prover.bin` is emitted:
//! the prover always builds from source so a poisoned artifact cannot
//! exfiltrate the secret through the proof's public-input list.

use anyhow::{anyhow, Result};
use ownership_circuit::circuit::circuit_logic::OwnershipCircuit;
use plonky2::util::serialization::DefaultGateSerializer;
use std::fs;
use std::path::Path;
use zk_circuits_common::circuit::ownership_circuit_config;

/// Generate ownership-circuit verifier binaries (`verifier.bin`, `common.bin`).
pub fn generate_circuit_binaries<P: AsRef<Path>>(output_dir: P) -> Result<()> {
    println!("Building ownership circuit (ZK)...");
    let circuit = OwnershipCircuit::new(ownership_circuit_config())?;
    let circuit_data = circuit.build_circuit();
    println!("Circuit built.");

    let output_path = output_dir.as_ref();
    fs::create_dir_all(output_path)?;

    let verifier_data = circuit_data.verifier_data();
    let common_bytes = verifier_data
        .common
        .to_bytes(&DefaultGateSerializer)
        .map_err(|e| anyhow!("failed to serialize common data: {}", e))?;
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize verifier data: {}", e))?;

    fs::write(output_path.join("common.bin"), &common_bytes)?;
    fs::write(output_path.join("verifier.bin"), &verifier_only_bytes)?;

    println!("Common data saved to {}/common.bin", output_path.display());
    println!(
        "Verifier data saved to {}/verifier.bin",
        output_path.display()
    );

    Ok(())
}
