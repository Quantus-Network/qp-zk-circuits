//! Build + serialize public-batch aggregation circuit artifacts.
//!
//! Generates: `public_batch_common.bin`, `public_batch_verifier.bin`
//! No `public_batch_prover.bin` is emitted: `PublicBatchProver` always rebuilds
//! the circuit from source, because a poisoned prover artifact could exfiltrate
//! witness data through the proof's public-input list.
//!
//! Expects private-batch artifacts to already exist in `output_dir`.

use anyhow::{anyhow, Context, Result};
use std::fs::{self, create_dir_all};
use std::io::Write as _;
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
///
/// The two public-batch files are published all-or-nothing (see
/// [`commit_artifact_set`]), so a failed re-run over an existing bins dir
/// never leaves a fresh `public_batch_common.bin` beside a stale
/// `public_batch_verifier.bin`. Whole-directory consistency across all
/// stages (leaf, private-batch, public-batch, `config.json`) is still only
/// guaranteed by the staging `generate_all_circuit_binaries` flow in
/// `circuit-builder`; prefer it unless deliberately regenerating this one
/// stage into an existing set.
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

    commit_artifact_set(
        bins_dir,
        &[
            ("public_batch_common.bin", common_bytes),
            ("public_batch_verifier.bin", verifier_bytes),
        ],
    )
}

/// Publish a matched set of artifact files into `bins_dir` all-or-nothing.
///
/// `public_batch_common.bin` and `public_batch_verifier.bin` are consumed as a
/// matched pair (loaders pin them against a canonical circuit rebuild), so a
/// directory holding a fresh file from one generation beside a stale file from
/// another is rejected until regenerated. Naive in-place writes create exactly
/// that state whenever a re-run fails between files.
///
/// Instead, every file is first staged under a fresh unpredictable temp name
/// in the same directory (exclusive create, so a pre-planted entry or symlink
/// is never adopted), and only after all stages succeed are the previous
/// artifacts moved aside and the staged files renamed into place. Any failure
/// rolls the moved-aside originals back, so an error always leaves either the
/// complete previous set or the complete new set — never a mix. The unwritten
/// window shrinks from the whole multi-minute build-and-write to the instants
/// between renames of already-complete files.
fn commit_artifact_set(bins_dir: &Path, files: &[(&str, Vec<u8>)]) -> Result<()> {
    let unique = format!("{}-{:016x}", std::process::id(), rand::random::<u64>());
    let tmp_path = |name: &str| bins_dir.join(format!(".{name}.tmp-{unique}"));
    let old_path = |name: &str| bins_dir.join(format!(".{name}.old-{unique}"));

    // Phase 1: stage every file. Any failure here leaves the originals untouched.
    for (i, (name, bytes)) in files.iter().enumerate() {
        let path = tmp_path(name);
        let staged = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| f.write_all(bytes));
        if let Err(e) = staged {
            for (name, _) in &files[..=i] {
                let _ = fs::remove_file(tmp_path(name));
            }
            return Err(e).with_context(|| format!("Failed to stage {}", path.display()));
        }
    }

    // Phase 2: move previous artifacts aside, then swap the staged set in.
    let mut moved_aside: Vec<&str> = Vec::new();
    let mut swapped: Vec<&str> = Vec::new();
    let swap_result = (|| -> Result<()> {
        for (name, _) in files {
            match fs::rename(bins_dir.join(name), old_path(name)) {
                Ok(()) => moved_aside.push(name),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("Failed to move previous {} aside", bins_dir.join(name).display())
                    })
                }
            }
        }
        for (name, _) in files {
            fs::rename(tmp_path(name), bins_dir.join(name)).with_context(|| {
                format!(
                    "Failed to move staged artifact into place at {}",
                    bins_dir.join(name).display()
                )
            })?;
            swapped.push(name);
        }
        Ok(())
    })();

    match swap_result {
        Ok(()) => {
            // The new set is committed; the moved-aside copies are redundant.
            for name in moved_aside {
                let old = old_path(name);
                if fs::remove_file(&old).is_err() {
                    let _ = fs::remove_dir_all(&old);
                }
            }
            Ok(())
        }
        Err(e) => {
            // Restore the previous set: renaming the old copy back atomically
            // overwrites any already-swapped new file; names that had no old
            // copy get their new file removed instead.
            for (name, _) in files {
                let final_path = bins_dir.join(name);
                if moved_aside.contains(name) {
                    if fs::rename(old_path(name), &final_path).is_err() {
                        // A blocking entry (e.g. an already-swapped file under
                        // a directory-shaped old copy) must not strand the
                        // rollback in a mixed state.
                        let _ = fs::remove_file(&final_path);
                        let _ = fs::rename(old_path(name), &final_path);
                    }
                } else if swapped.contains(name) {
                    let _ = fs::remove_file(&final_path);
                }
                let _ = fs::remove_file(tmp_path(name));
            }
            Err(e)
        }
    }
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

