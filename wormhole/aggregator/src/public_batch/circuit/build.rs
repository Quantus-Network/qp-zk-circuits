//! Build + serialize public-batch aggregation circuit artifacts.
//!
//! Generates: `public_batch_common.bin`, `public_batch_verifier.bin`, `public_batch_prover.bin` (optional)
//!
//! Expects private-batch artifacts to already exist in `output_dir`.

use anyhow::{anyhow, Context, Result};
use std::fs::{create_dir_all, write};
use std::path::Path;

use plonky2::plonk::circuit_data::{
    CommonCircuitData, ProverCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};

use qp_wormhole_inputs::validate_proof_count;
use zk_circuits_common::circuit::{wormhole_public_batch_circuit_config, C, D, F};

use crate::common::utils::private_batch_num_leaves_from_padded_pi_len;
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;

/// Build and write all public-batch artifacts into `output_dir`.
pub fn generate_public_batch_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_private_batch_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_dir = output_dir.as_ref();
    // Bound the per-layer count before any circuit construction (#97021, #97070).
    validate_proof_count(num_private_batch_proofs, "num_private_batch_proofs")?;
    create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    let private_batch_common = load_private_batch_common_from_bins(output_dir)
        .context("Failed to load private-batch common circuit data")?;
    let private_batch_verifier_only = load_private_batch_verifier_only_from_bins(output_dir)
        .context("Failed to load private-batch verifier data")?;

    let private_batch_num_leaves =
        private_batch_num_leaves_from_padded_pi_len(private_batch_common.num_public_inputs)?;

    // Non-ZK config: public-batch witnesses (private-batch proofs) are already public data and their
    // public inputs are forwarded verbatim, so blinding buys nothing and slows proving.
    let public_batch_circuit = PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private_batch_common,
        &private_batch_verifier_only,
        num_private_batch_proofs,
        private_batch_num_leaves,
    );

    let circuit_data = public_batch_circuit.build_circuit();
    let verifier_data = circuit_data.verifier_data();
    write_verifier_artifacts(output_dir, &verifier_data)?;

    if include_prover {
        let prover_data = circuit_data.prover_data();
        write_prover_artifact(output_dir, &prover_data)?;
    }

    println!(
        "Public-batch circuit artifacts written to {} (num_private_batch_proofs={}, private_batch_num_leaves={})",
        output_dir.display(),
        num_private_batch_proofs,
        private_batch_num_leaves
    );

    Ok(())
}

fn load_private_batch_common_from_bins(bins_dir: &Path) -> Result<CommonCircuitData<F, D>> {
    let gate_serializer = DefaultGateSerializer;

    let bytes = std::fs::read(bins_dir.join("private_batch_common.bin")).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join("private_batch_common.bin").display()
        )
    })?;

    CommonCircuitData::from_bytes(bytes, &gate_serializer)
        .map_err(|e| anyhow!("Failed to deserialize private_batch_common.bin: {}", e))
}

fn load_private_batch_verifier_only_from_bins(
    bins_dir: &Path,
) -> Result<VerifierOnlyCircuitData<C, D>> {
    let bytes = std::fs::read(bins_dir.join("private_batch_verifier.bin")).with_context(|| {
        format!(
            "Failed to read {}",
            bins_dir.join("private_batch_verifier.bin").display()
        )
    })?;

    VerifierOnlyCircuitData::from_bytes(bytes)
        .map_err(|e| anyhow!("Failed to deserialize private_batch_verifier.bin: {}", e))
}

fn write_verifier_artifacts(
    bins_dir: &Path,
    verifier_data: &VerifierCircuitData<F, C, D>,
) -> Result<()> {
    let gate_serializer = DefaultGateSerializer;

    let common_bytes = verifier_data
        .common
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize public_batch common data: {}", e))?;

    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize public_batch verifier data: {}", e))?;

    write(bins_dir.join("public_batch_common.bin"), common_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            bins_dir.join("public_batch_common.bin").display()
        )
    })?;
    write(bins_dir.join("public_batch_verifier.bin"), verifier_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            bins_dir.join("public_batch_verifier.bin").display()
        )
    })?;

    Ok(())
}

fn write_prover_artifact(bins_dir: &Path, prover_data: &ProverCircuitData<F, C, D>) -> Result<()> {
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let prover_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, &prover_data.common)
        .map_err(|e| anyhow!("Failed to serialize public_batch prover data: {}", e))?;

    write(bins_dir.join("public_batch_prover.bin"), prover_bytes).with_context(|| {
        format!(
            "Failed to write {}",
            bins_dir.join("public_batch_prover.bin").display()
        )
    })?;

    Ok(())
}
