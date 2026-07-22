//! Build + serialize public-batch aggregation circuit artifacts.
//!
//! Generates: `public_batch_common.bin`, `public_batch_verifier.bin`
//! No `public_batch_prover.bin` is emitted: `PublicBatchProver` always rebuilds
//! the circuit from source, because a poisoned prover artifact could exfiltrate
//! witness data through the proof's public-input list.
//!
//! Expects private-batch artifacts to already exist in `output_dir`.

use anyhow::{anyhow, Context, Result};
use std::fs::{create_dir_all, write};
use std::path::Path;

use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::util::serialization::DefaultGateSerializer;

use qp_wormhole_inputs::validate_proof_count;
use zk_circuits_common::circuit::{wormhole_public_batch_circuit_config, C, D, F};

use crate::common::utils::{
    canonical_leaf_verifier_data, load_canonical_private_batch_verifier_data,
    private_batch_num_leaves_from_padded_pi_len, read_artifact_file,
};
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;

/// Build and write all public-batch artifacts into `output_dir`.
pub fn generate_public_batch_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_private_batch_proofs: usize,
) -> Result<()> {
    let output_dir = output_dir.as_ref();
    // Bound the per-layer count before any circuit construction (#97021, #97070).
    validate_proof_count(num_private_batch_proofs, "num_private_batch_proofs")?;
    create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    // Pin the private-batch artifacts to the canonical private-batch circuit BEFORE
    // baking their verifier key into the public-batch circuit as constants. The leaf
    // count is derived from the (untrusted) common data first, but the subsequent
    // byte-exact comparison against a canonically rebuilt circuit for that count
    // rejects any substituted or stale artifact.
    let private_batch_common_bytes = read_artifact_file(&output_dir.join("private_batch_common.bin"))
        .with_context(|| {
            format!(
                "Failed to read {}",
                output_dir.join("private_batch_common.bin").display()
            )
        })?;
    let private_batch_verifier_bytes =
        read_artifact_file(&output_dir.join("private_batch_verifier.bin")).with_context(|| {
            format!(
                "Failed to read {}",
                output_dir.join("private_batch_verifier.bin").display()
            )
        })?;

    let claimed_pi_len = peek_common_num_public_inputs(&private_batch_common_bytes)?;
    let private_batch_num_leaves = private_batch_num_leaves_from_padded_pi_len(claimed_pi_len)?;

    let private_batch = load_canonical_private_batch_verifier_data(
        &private_batch_common_bytes,
        &private_batch_verifier_bytes,
        &canonical_leaf_verifier_data(),
        private_batch_num_leaves,
    )
    .context("Failed to load private-batch verifier data")?;

    // Non-ZK config: public-batch witnesses (private-batch proofs) are already public data and their
    // public inputs are forwarded verbatim, so blinding buys nothing and slows proving.
    let public_batch_circuit = PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private_batch.common,
        &private_batch.verifier_only,
        num_private_batch_proofs,
        private_batch_num_leaves,
    )?;

    let verifier_data = public_batch_circuit.build_verifier();
    write_verifier_artifacts(output_dir, &verifier_data)?;

    println!(
        "Public-batch circuit artifacts written to {} (num_private_batch_proofs={}, private_batch_num_leaves={})",
        output_dir.display(),
        num_private_batch_proofs,
        private_batch_num_leaves
    );

    Ok(())
}

/// Decode the claimed public-input count from serialized common circuit data.
///
/// Used only to derive the leaf count needed to rebuild the canonical
/// private-batch circuit; the artifact is then pinned byte-exactly against that
/// canonical rebuild, so a lie here cannot survive the comparison.
fn peek_common_num_public_inputs(common_bytes: &[u8]) -> Result<usize> {
    let gate_serializer = DefaultGateSerializer;
    let common = plonky2::plonk::circuit_data::CommonCircuitData::<F, D>::from_bytes(
        common_bytes.to_vec(),
        &gate_serializer,
    )
    .map_err(|e| anyhow!("Failed to deserialize private_batch_common.bin: {}", e))?;
    Ok(common.num_public_inputs)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::MAX_ARTIFACT_FILE_BYTES;
    use std::fs::File;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qp-public-batch-build-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_all(&dir).unwrap();
        dir
    }

    /// An oversized (sparse) private-batch artifact must be rejected by the
    /// size cap before its contents are allocated into memory and fed into
    /// `peek_common_num_public_inputs`'s full deserialization.
    #[test]
    fn oversized_private_batch_common_artifact_is_rejected_by_size_cap() {
        let dir = temp_dir("oversized-common");
        File::create(dir.join("private_batch_common.bin"))
            .unwrap()
            .set_len(MAX_ARTIFACT_FILE_BYTES + 1)
            .unwrap();
        std::fs::write(dir.join("private_batch_verifier.bin"), b"irrelevant").unwrap();

        let err = generate_public_batch_circuit_binaries(&dir, 1).unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds the"),
            "oversized artifact must be rejected by the size cap, got: {err:#}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

