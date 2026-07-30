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
    read_artifact_file, sweep_stale_artifact_droppings,
};
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;

/// Build and write all public-batch artifacts into `output_dir`.
///
/// The two public-batch files are published all-or-nothing (see
/// [`commit_artifact_set`]), so a failed re-run over an existing bins dir
/// never leaves a fresh `public_batch_common.bin` beside a stale
/// `public_batch_verifier.bin`. Whole-directory consistency across all
/// stages (leaf, private-batch, public-batch, `config.json`) is still only
/// guaranteed by the staging `generate_all_circuit_binaries` flow in
/// `circuit-builder`; prefer it unless deliberately regenerating this one
/// stage into an existing set.
///
/// `num_leaf_proofs` is the private-batch leaf count the on-disk
/// `private_batch_*.bin` artifacts were built for. It is taken from the
/// caller (who already knows it — typically
/// [`crate::config::CircuitBinsConfig`]) rather than peeked out of the
/// untrusted common artifact: reading `num_public_inputs` via a full
/// `CommonCircuitData::from_bytes` asked the allocator for capacities from
/// attacker-controlled length fields before canonical pinning could reject
/// the file (audit finding).
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
    // A previous publish hard-killed mid-swap leaves orphaned temp/backup
    // entries behind; we are about to replace the set, so sweep them now.
    sweep_stale_artifact_droppings(output_dir)?;

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

    // Published all-or-nothing; see `commit_artifact_set` in `common::utils`.
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
    use test_helpers::fake_leaf::build_fake_leaf_circuit;

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

    /// `public_batch_common.bin` and `public_batch_verifier.bin` are a matched
    /// set: consumers load both and pin them against a canonical rebuild, so a
    /// directory holding one new file beside one stale file is rejected until
    /// regenerated. A publish that fails partway must therefore either leave
    /// the previous set fully intact or replace it wholesale — never mix.
    #[test]
    fn failed_artifact_publish_never_leaves_mixed_verifier_set() {
        let dir = temp_dir("mixed-set");
        std::fs::write(dir.join("public_batch_common.bin"), b"old common").unwrap();
        // A directory squatting on the verifier path makes a naive in-place
        // write of the second file fail after the first was already clobbered.
        create_dir_all(dir.join("public_batch_verifier.bin")).unwrap();

        let verifier_data = build_fake_leaf_circuit().0.verifier_data();
        let result = write_verifier_artifacts(&dir, &verifier_data);

        let common_now = std::fs::read(dir.join("public_batch_common.bin")).unwrap();
        match result {
            Err(_) => assert_eq!(
                common_now, b"old common",
                "a failed publish must leave the previous artifact set untouched, \
                 not a fresh common beside a stale verifier"
            ),
            Ok(()) => {
                assert_ne!(
                    common_now, b"old common",
                    "a successful publish must replace the set wholesale"
                );
                assert!(
                    dir.join("public_batch_verifier.bin").is_file(),
                    "a successful publish must leave a real verifier artifact"
                );
            }
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A symlink pre-planted at an artifact filename must not redirect the
    /// write onto its target (audit finding: symlink-following artifact
    /// writes). `commit_artifact_set` stages under exclusive-create temp names
    /// and renames into place, which replaces the planted entry itself; this
    /// guards against regressing to direct `std::fs::write` calls.
    #[cfg(unix)]
    #[test]
    fn artifact_writes_do_not_follow_planted_symlinks() {
        let dir = temp_dir("symlink-clobber");

        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"precious data").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("public_batch_verifier.bin")).unwrap();

        let verifier_data = build_fake_leaf_circuit().0.verifier_data();
        let result = write_verifier_artifacts(&dir, &verifier_data);

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"precious data",
            "artifact publication must never write through a planted symlink"
        );
        if result.is_ok() {
            let verifier = std::fs::read(dir.join("public_batch_verifier.bin")).unwrap();
            assert_ne!(
                verifier, b"precious data",
                "a successful run must have replaced the planted entry with a real artifact"
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A publish hard-killed mid-swap (SIGKILL/power loss) leaves orphaned
    /// `.<name>.tmp-*` / `.<name>.old-*` droppings that no later run adopts
    /// (the random suffix is fresh per call). The builder path must sweep
    /// them before regenerating so they do not accumulate forever (audit
    /// finding: crash-path droppings never cleaned up). Unrelated dotfiles
    /// must survive the sweep.
    #[test]
    fn rebuild_sweeps_droppings_of_interrupted_publish() {
        let dir = temp_dir("crash-droppings");

        // Simulate the post-SIGKILL state: originals moved aside, staged
        // files still present, nothing live. Generation will fail for lack of
        // private-batch artifacts, but the sweep must still run first.
        let dropping_old = dir.join(".public_batch_common.bin.old-12345-0123456789abcdef");
        let dropping_tmp = dir.join(".public_batch_verifier.bin.tmp-12345-0123456789abcdef");
        std::fs::write(&dropping_old, b"moved-aside original").unwrap();
        std::fs::write(&dropping_tmp, b"orphaned staged file").unwrap();
        let innocent = dir.join(".gitignore");
        std::fs::write(&innocent, b"*.log").unwrap();

        let _ = generate_public_batch_circuit_binaries(&dir, 1, 1);

        assert!(
            !dropping_old.exists() && !dropping_tmp.exists(),
            "regeneration must sweep droppings of an interrupted publish"
        );
        assert!(
            innocent.exists(),
            "the sweep must not touch unrelated dotfiles"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A successful re-publish over an existing set must replace both files
    /// and leave no staging or moved-aside droppings behind in the bins dir.
    #[test]
    fn artifact_publish_replaces_set_wholesale_without_droppings() {
        let dir = temp_dir("clean-publish");
        std::fs::write(dir.join("public_batch_common.bin"), b"old common").unwrap();
        std::fs::write(dir.join("public_batch_verifier.bin"), b"old verifier").unwrap();

        let verifier_data = build_fake_leaf_circuit().0.verifier_data();
        write_verifier_artifacts(&dir, &verifier_data).unwrap();

        assert_ne!(
            std::fs::read(dir.join("public_batch_common.bin")).unwrap(),
            b"old common"
        );
        assert_ne!(
            std::fs::read(dir.join("public_batch_verifier.bin")).unwrap(),
            b"old verifier"
        );
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "public_batch_common.bin".to_string(),
                "public_batch_verifier.bin".to_string()
            ],
            "publish must not leave temp/old files behind"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
