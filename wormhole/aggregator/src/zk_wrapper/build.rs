//! Build helpers for ZK wrapper circuit binaries.
//!
//! Generates:
//! - `wrapper_common.bin`
//! - `wrapper_verifier.bin`  
//! - `wrapper_prover.bin`

use anyhow::{anyhow, Context, Result};
use plonky2::{
    plonk::circuit_data::CommonCircuitData,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use std::{
    fs::{create_dir_all, write},
    path::Path,
};

use zk_circuits_common::circuit::{wormhole_aggregator_circuit_config, C, D, F};

use super::circuit::ZkWrapperCircuit;

/// Generate ZK wrapper circuit binaries.
///
/// # Expected inputs (already generated in `output_dir`)
/// - `aggregated_nonzk_common.bin` (non-ZK L0 common data)
///
/// # Outputs (written to `output_dir`)
/// - `wrapper_common.bin`
/// - `wrapper_verifier.bin`
/// - `wrapper_prover.bin`
pub fn generate_wrapper_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    println!("Building ZK wrapper circuit...");

    // Load the non-ZK L0 common data (the circuit we're wrapping)
    let inner_common = load_common_data(&output_path.join("aggregated_nonzk_common.bin"))?;

    // Build the ZK wrapper circuit
    let wrapper_config = wormhole_aggregator_circuit_config(); // ZK config
    let wrapper_circuit = ZkWrapperCircuit::new(wrapper_config, inner_common);
    let circuit_data = wrapper_circuit.build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // Serialize wrapper_common.bin
    let wrapper_common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize wrapper common data: {}", e))?;
    write(output_path.join("wrapper_common.bin"), wrapper_common_bytes)?;
    println!("Saved {}/wrapper_common.bin", output_path.display());

    // Serialize wrapper_verifier.bin
    let wrapper_verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize wrapper verifier data: {}", e))?;
    write(
        output_path.join("wrapper_verifier.bin"),
        wrapper_verifier_bytes,
    )?;
    println!("Saved {}/wrapper_verifier.bin", output_path.display());

    // Serialize wrapper_prover.bin
    if include_prover {
        let wrapper_prover_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize wrapper prover data: {}", e))?;
        write(output_path.join("wrapper_prover.bin"), wrapper_prover_bytes)?;
        println!("Saved {}/wrapper_prover.bin", output_path.display());
    } else {
        println!("Skipping wrapper prover binary generation");
    }

    Ok(())
}

/// Load common circuit data from disk.
fn load_common_data(common_path: &Path) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = std::fs::read(common_path)
        .with_context(|| format!("Failed to read common circuit file {:?}", common_path))?;

    CommonCircuitData::from_bytes(common_bytes, &gate_serializer).map_err(|e| {
        anyhow!(
            "Failed to deserialize common circuit data from {:?}: {}",
            common_path,
            e
        )
    })
}
