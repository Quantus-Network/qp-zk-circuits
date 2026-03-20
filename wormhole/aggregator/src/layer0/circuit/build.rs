//! Prebuild / serialization helpers for the monolithic Layer-0 aggregation circuit.
//!
//! This generates the prebuilt circuit artifacts used by `Layer0AggregationProver` and verifier:
//! - `aggregated_common.bin`
//! - `aggregated_verifier.bin`
//! - `aggregated_prover.bin`
//!
//! It expects the leaf circuit `common.bin` to already exist in the same output directory.

use anyhow::{anyhow, Context, Result};
use plonky2::{
    plonk::config::PoseidonGoldilocksConfig,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use std::{
    fs::{create_dir_all, write},
    path::Path,
};
use zk_circuits_common::circuit::wormhole_circuit_config;

use zk_circuits_common::circuit::{D, F};

use crate::layer0::circuit::circuit_logic::Layer0AggregationCircuit;

/// Generate prebuilt Layer-0 aggregation circuit binaries + target layout.
///
/// # Expected inputs (already generated in `output_dir`)
/// - `common.bin` (leaf common circuit data)
///
/// # Outputs (written to `output_dir`)
/// - `aggregated_common.bin`
/// - `aggregated_verifier.bin`
/// - `aggregated_prover.bin`
///
/// # Notes
/// This builds a monolithic aggregation circuit that verifies `num_leaf_proofs` leaf proofs
/// directly and applies the wormhole layer-0 wrapper logic. The resulting artifacts can be
/// loaded by `Layer0AggregationProver::new_from_binaries_dir(...)` without rebuilding the
/// aggregation circuit at proving time.
pub fn generate_layer0_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    println!(
        "Building prebuilt layer-0 aggregation circuit (num_leaf_proofs={})...",
        num_leaf_proofs
    );

    // Load leaf common data (needed to allocate and verify leaf proof targets in the layer-0 circuit)
    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;

    // Build monolithic layer-0 aggregation circuit
    let agg_circuit =
        Layer0AggregationCircuit::new(wormhole_circuit_config(), leaf_common, num_leaf_proofs);

    // Build full circuit so we can serialize verifier + prover + common
    let circuit_data = agg_circuit.build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // -------------------------------------------------------------------------
    // Serialize aggregated common.bin
    // -------------------------------------------------------------------------
    let agg_common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize aggregated common data: {}", e))?;
    write(output_path.join("aggregated_common.bin"), agg_common_bytes)?;
    println!("Saved {}/aggregated_common.bin", output_path.display());

    // -------------------------------------------------------------------------
    // Serialize aggregated verifier.bin
    // -------------------------------------------------------------------------
    let agg_verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;
    write(
        output_path.join("aggregated_verifier.bin"),
        agg_verifier_only_bytes,
    )?;
    println!("Saved {}/aggregated_verifier.bin", output_path.display());

    // -------------------------------------------------------------------------
    // Serialize aggregated prover.bin
    // -------------------------------------------------------------------------
    if include_prover {
        let agg_prover_only_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize aggregated prover data: {}", e))?;
        write(
            output_path.join("aggregated_prover.bin"),
            agg_prover_only_bytes,
        )?;
        println!("Saved {}/aggregated_prover.bin", output_path.display());
    } else {
        println!("Skipping aggregated prover binary generation");
    }
    Ok(())
}

/// Load leaf `common.bin` from disk.
///
/// This is the leaf wormhole circuit's common data, used to define proof targets and
/// verification constraints in the layer-0 aggregation circuit.
fn load_leaf_common_data(
    common_path: &Path,
) -> Result<plonky2::plonk::circuit_data::CommonCircuitData<F, D>> {
    use plonky2::plonk::circuit_data::CommonCircuitData;

    let gate_serializer = DefaultGateSerializer;

    let common_bytes = std::fs::read(common_path)
        .with_context(|| format!("Failed to read leaf common circuit file {:?}", common_path))?;

    CommonCircuitData::from_bytes(common_bytes, &gate_serializer).map_err(|e| {
        anyhow!(
            "Failed to deserialize leaf common circuit data from {:?}: {}",
            common_path,
            e
        )
    })
}
