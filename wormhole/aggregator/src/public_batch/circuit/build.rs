//! Build + serialize public-batch aggregation circuit artifacts.
//!
//! Generates: `public_batch_common.bin`, `public_batch_verifier.bin`
//! No `public_batch_prover.bin` is emitted: `PublicBatchProver` always rebuilds
//! the circuit from source, because a poisoned prover artifact could exfiltrate
//! witness data through the proof's public-input list.
//!
//! Expects private-batch artifacts to already exist in `output_dir`.

use anyhow::{anyhow, Context, Result};
use std::fs::create_dir_all;
use std::path::Path;

use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::util::serialization::DefaultGateSerializer;

use qp_wormhole_inputs::validate_proof_count;
use zk_circuits_common::circuit::{wormhole_public_batch_circuit_config, C, D, F};

use crate::common::utils::{
    canonical_leaf_verifier_data, commit_artifact_set, load_canonical_private_batch_verifier_data,
    read_artifact_file,
};
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;

/// Build and write all public-batch artifacts into `output_dir`.
///
/// Writes public-batch verifier artifacts. Prefer
/// `generate_all_circuit_binaries` for production regenerates
/// (`wormhole/THREAT_MODEL.md`).
///
/// `num_leaf_proofs` is the private-batch leaf count the on-disk
/// `private_batch_*.bin` artifacts were built for (caller-supplied;
/// typically [`crate::config::CircuitBinsConfig`]).
pub fn generate_public_batch_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_private_batch_proofs: usize,
    num_leaf_proofs: usize,
) -> Result<()> {
    let output_dir = output_dir.as_ref();
    // Bound the per-layer counts before any circuit construction (#97021, #97070).
    validate_proof_count(num_private_batch_proofs, "num_private_batch_proofs")?;
    validate_proof_count(num_leaf_proofs, "num_leaf_proofs")?;
    create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    // Pin the private-batch artifacts to the canonical private-batch circuit
    // BEFORE baking their verifier key into the public-batch circuit as
    // constants. Pinning compares the raw artifact bytes to a canonical
    // rebuild for `num_leaf_proofs` and never deserializes the untrusted
    // common data (see `load_canonical_private_batch_verifier_data`).
    let private_batch_common_bytes =
        read_artifact_file(&output_dir.join("private_batch_common.bin")).with_context(|| {
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

    let private_batch = load_canonical_private_batch_verifier_data(
        &private_batch_common_bytes,
        &private_batch_verifier_bytes,
        &canonical_leaf_verifier_data(),
        num_leaf_proofs,
    )
    .context("Failed to load private-batch verifier data")?;

    // Non-ZK config: public-batch witnesses (private-batch proofs) are already public data and their
    // public inputs are forwarded verbatim, so blinding buys nothing and slows proving.
    let public_batch_circuit = PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private_batch.common,
        &private_batch.verifier_only,
        num_private_batch_proofs,
        num_leaf_proofs,
    )?;

    let verifier_data = public_batch_circuit.build_verifier();
    write_verifier_artifacts(output_dir, &verifier_data)?;

    println!(
        "Public-batch circuit artifacts written to {} (num_private_batch_proofs={}, private_batch_num_leaves={})",
        output_dir.display(),
        num_private_batch_proofs,
        num_leaf_proofs
    );

    Ok(())
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

    // Prefer whole-dir staging via `generate_all_circuit_binaries` for production.
    commit_artifact_set(
        bins_dir,
        &[
            ("public_batch_common.bin", common_bytes),
            ("public_batch_verifier.bin", verifier_bytes),
        ],
        &[],
    )
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
    /// size cap before its contents are allocated into memory.
    #[test]
    fn oversized_private_batch_common_artifact_is_rejected_by_size_cap() {
        let dir = temp_dir("oversized-common");
        File::create(dir.join("private_batch_common.bin"))
            .unwrap()
            .set_len(MAX_ARTIFACT_FILE_BYTES + 1)
            .unwrap();
        std::fs::write(dir.join("private_batch_verifier.bin"), b"irrelevant").unwrap();

        let err = generate_public_batch_circuit_binaries(&dir, 1, 1).unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds the"),
            "oversized artifact must be rejected by the size cap, got: {err:#}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A capped-but-poisoned `private_batch_common.bin` whose serialized
    /// length fields would force huge `try_reserve` calls under a full
    /// `CommonCircuitData::from_bytes` must be rejected by the byte-exact
    /// canonical pin — never deserialized for a leaf-count peek (audit
    /// finding). Sprinkling enormous little-endian usizes through a small
    /// buffer covers whatever offset the first length-prefixed vector occupies.
    #[test]
    fn poisoned_private_batch_common_is_rejected_without_deserialize_peek() {
        let dir = temp_dir("poisoned-common");
        let mut poisoned = vec![0u8; 4096];
        for i in (0..poisoned.len()).step_by(8) {
            poisoned[i..i + 8].copy_from_slice(&(usize::MAX / 16).to_le_bytes());
        }
        std::fs::write(dir.join("private_batch_common.bin"), &poisoned).unwrap();
        std::fs::write(dir.join("private_batch_verifier.bin"), &poisoned[..128]).unwrap();

        let err = generate_public_batch_circuit_binaries(&dir, 1, 1).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("does not match the canonical"),
            "poisoned common must fail the byte pin (not a deserialize OOM/IoError), got: {chain}"
        );
        assert!(
            !dir.join("public_batch_common.bin").exists()
                && !dir.join("public_batch_verifier.bin").exists(),
            "a rejected private-batch pin must not publish public-batch artifacts"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
