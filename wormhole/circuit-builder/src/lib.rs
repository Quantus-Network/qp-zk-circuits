use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::fs::{create_dir_all, write};
use std::path::{Path, PathBuf};
use wormhole_aggregator::public_batch::circuit::generate_public_batch_circuit_binaries;

use plonky2::util::serialization::DefaultGateSerializer;
use wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::wormhole_leaf_circuit_config;

// Re-export CircuitBinsConfig from aggregator so users of circuit-builder can access it
pub use wormhole_aggregator::CircuitBinsConfig;

/// Generate only the leaf wormhole circuit binaries.
///
/// This is a low-level helper for partial artifact generation. For the full flow that also
/// emits `config.json`, use [`generate_all_circuit_binaries`].
///
/// WARNING: writes into `output_dir` in place, without clearing pre-existing
/// files or staging a complete set first. Interrupted or partial runs can
/// leave a mixed artifact set. [`generate_all_circuit_binaries`] stages and
/// atomically replaces the directory instead; prefer it unless you are
/// deliberately regenerating one stage into an existing set.
///
/// Note: no `prover.bin` is emitted for the leaf circuit. `WormholeProver` always builds
/// the (small, fast-to-build) leaf circuit from source; loading prover-only artifacts was
/// removed because a poisoned artifact could exfiltrate private witness data through the
/// proof's public-input list.
pub fn generate_circuit_binaries<P: AsRef<Path>>(output_dir: P) -> Result<()> {
    println!("Building wormhole leaf circuit (non-ZK for faster proving)...");
    let config = wormhole_leaf_circuit_config();
    let circuit = WormholeCircuit::new(config);
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();
    println!("Circuit built.");

    let gate_serializer = DefaultGateSerializer;

    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    // Generate dummy proof BEFORE consuming circuit_data (prove() borrows, prover_data() moves)
    println!("Generating dummy proof for aggregation padding...");
    let dummy_proof_bytes = wormhole_aggregator::generate_dummy_proof(&circuit_data, &targets)
        .map_err(|e| anyhow!("failed to generate dummy proof: {}", e))?;
    write(output_path.join("dummy_proof.bin"), &dummy_proof_bytes)?;
    println!(
        "Dummy proof saved to {}/dummy_proof.bin ({} bytes)",
        output_path.display(),
        dummy_proof_bytes.len()
    );

    println!("Serializing circuit data...");

    let verifier_data = circuit_data.verifier_data();
    let common_data = &verifier_data.common;

    // Serialize common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize common data: {}", e))?;
    write(output_path.join("common.bin"), common_bytes)?;
    println!("Common data saved to {}/common.bin", output_path.display());

    // Serialize verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize verifier data: {}", e))?;
    write(output_path.join("verifier.bin"), verifier_only_bytes)?;
    println!(
        "Verifier data saved to {}/verifier.bin",
        output_path.display()
    );

    Ok(())
}

/// Generate all circuit binaries (both regular and aggregated)
///
/// The full artifact set is staged in a temporary sibling directory and only
/// swapped into `output_dir` once every stage (leaf, private-batch, optional
/// public-batch, `config.json`) has succeeded. A failed serialization, killed
/// process, or interrupted rerun therefore never leaves `output_dir` holding a
/// mix of new and stale files: it either keeps its previous contents or
/// receives the complete new set. Any pre-existing contents of `output_dir`
/// are replaced wholesale on success.
///
/// # Arguments
/// * `output_dir` - Directory to write the binaries to
/// * `include_prover` - Whether to include the prover binaries for the batch aggregation
///   circuits (the leaf circuit never emits a prover binary; see [`generate_circuit_binaries`])
/// * `num_leaf_proofs` - Number of leaf proofs aggregated into a single proof (must be > 0)
/// * `num_private_batch_proofs` - Optional param for number of inner proofs (for public-batch circuit). Set to none if you only want private-batch aggregation.
///
/// # Errors
/// Returns an error if proof counts are invalid (zero or exceed maximum bounds).
/// Validation happens before any files are written to avoid partial artifact generation.
pub fn generate_all_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
    num_leaf_proofs: usize,
    num_private_batch_proofs: Option<usize>,
) -> Result<()> {
    // Validate proof counts upfront before any writes to avoid partial artifact generation
    let config = CircuitBinsConfig::new(num_leaf_proofs, num_private_batch_proofs)?;

    let output_path = output_dir.as_ref();
    let staging_path = staging_dir_for(output_path)?;

    let generated = (|| -> Result<()> {
        // Generate regular circuit binaries
        generate_circuit_binaries(&staging_path)?;

        // Generate aggregated circuit binaries
        generate_private_batch_circuit_binaries(
            &staging_path,
            config.num_leaf_proofs,
            include_prover,
        )?;

        // If num_private_batch_proofs is specified, generate public-batch aggregation circuit binaries
        if let Some(num_private_batch_proofs) = config.num_private_batch_proofs {
            generate_public_batch_circuit_binaries(
                &staging_path,
                num_private_batch_proofs,
                include_prover,
            )?;
        }

        // Save config file alongside binaries. Written last: its presence marks
        // the staged set as complete.
        config.save(&staging_path)
    })();

    if let Err(e) = generated {
        // A partial stage is worthless; never leave a stray staging directory
        // behind. (The commit phase below manages its own cleanup: once the
        // previous output set has been moved aside, the staged artifacts may
        // be the only surviving copy and must NOT be blindly deleted.)
        let _ = fs::remove_dir_all(&staging_path);
        return Err(e);
    }

    commit_staging_dir(&staging_path, output_path)
}

/// A unique staging directory on the same filesystem as `output_dir` (a
/// sibling), so the final `rename` is atomic.
fn staging_dir_for(output_dir: &Path) -> Result<PathBuf> {
    let Some(name) = output_dir.file_name().and_then(|n| n.to_str()) else {
        bail!(
            "output dir {} has no usable directory name; pass an explicit directory path",
            output_dir.display()
        );
    };
    Ok(output_dir.with_file_name(format!(".{}.staging-{}", name, std::process::id())))
}

/// Replace `output_dir` with the fully staged `staging_dir` via directory
/// renames. `rename` cannot overwrite a non-empty directory, so a pre-existing
/// output dir is first moved aside, then removed after the swap. A crash
/// between the renames leaves the old set aside and the new set staged — never
/// a directory mixing files from both generations.
///
/// Failure cleanup never deletes the only surviving artifact copy: if the
/// swap-in fails after the previous set was moved aside, the previous set is
/// rolled back into place (and only then is the redundant staged copy
/// removed); if even the rollback fails, both copies are left on disk and the
/// error reports their locations.
fn commit_staging_dir(staging_dir: &Path, output_dir: &Path) -> Result<()> {
    commit_staging_dir_impl(staging_dir, output_dir, |src, dst| fs::rename(src, dst))
}

/// [`commit_staging_dir`] with an injectable rename, so tests can force a
/// failure at each step of the swap and assert the cleanup guarantees.
fn commit_staging_dir_impl(
    staging_dir: &Path,
    output_dir: &Path,
    rename: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    let mut old_name = staging_dir.file_name().unwrap_or_default().to_os_string();
    old_name.push(".old");
    let old_path = staging_dir.with_file_name(old_name);
    let previous_exists = output_dir.exists();
    if previous_exists {
        if let Err(e) = rename(output_dir, &old_path) {
            // Nothing has moved: the previous set still serves from
            // output_dir, so the staged copy is safe to discard.
            let _ = fs::remove_dir_all(staging_dir);
            return Err(e).with_context(|| {
                format!(
                    "Failed to move previous artifact dir {} aside to {}",
                    output_dir.display(),
                    old_path.display()
                )
            });
        }
    }
    if let Err(e) = rename(staging_dir, output_dir) {
        // The previous set (if any) has been moved aside and output_dir is
        // empty, so the staged directory may hold the ONLY copy of the new
        // artifacts — never delete it before restoring something to
        // output_dir.
        if previous_exists {
            match rename(&old_path, output_dir) {
                Ok(()) => {
                    // Previous set restored; the staged copy is redundant.
                    let _ = fs::remove_dir_all(staging_dir);
                    return Err(e).with_context(|| {
                        format!(
                            "Failed to move staged artifacts {} into place at {} \
                             (previous artifacts were restored)",
                            staging_dir.display(),
                            output_dir.display()
                        )
                    });
                }
                Err(rollback_err) => {
                    return Err(e).with_context(|| {
                        format!(
                            "Failed to move staged artifacts {} into place at {}, and \
                             restoring the previous artifacts also failed ({}); previous \
                             artifacts remain at {}, new artifacts remain at {}",
                            staging_dir.display(),
                            output_dir.display(),
                            rollback_err,
                            old_path.display(),
                            staging_dir.display()
                        )
                    });
                }
            }
        }
        // No previous set existed: the staged directory is the only copy of
        // the artifacts at all; leave it for the operator.
        return Err(e).with_context(|| {
            format!(
                "Failed to move staged artifacts {} into place at {}; \
                 the built artifacts remain at {}",
                staging_dir.display(),
                output_dir.display(),
                staging_dir.display()
            )
        });
    }
    if previous_exists {
        // The new set is already committed at output_dir; failing to clean up
        // the old copy is an error but loses nothing.
        fs::remove_dir_all(&old_path).with_context(|| {
            format!(
                "Failed to remove previous artifact dir {}",
                old_path.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "qp-circuit-builder-test-{}-{}",
            tag,
            std::process::id()
        ))
    }

    /// The swap must replace stale contents wholesale, not merge into them.
    #[test]
    fn commit_replaces_existing_output_dir_wholesale() {
        let root = unique_tmp_dir("commit-replace");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        let staging = staging_dir_for(&output).unwrap();

        create_dir_all(&output).unwrap();
        write(output.join("stale.bin"), b"old artifact").unwrap();
        create_dir_all(&staging).unwrap();
        write(staging.join("fresh.bin"), b"new artifact").unwrap();

        commit_staging_dir(&staging, &output).unwrap();

        assert!(output.join("fresh.bin").exists());
        assert!(
            !output.join("stale.bin").exists(),
            "stale artifacts must not survive the swap"
        );
        assert!(!staging.exists(), "staging dir must be consumed");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_works_when_output_dir_does_not_exist() {
        let root = unique_tmp_dir("commit-fresh");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = staging_dir_for(&output).unwrap();

        create_dir_all(&staging).unwrap();
        write(staging.join("fresh.bin"), b"new artifact").unwrap();

        commit_staging_dir(&staging, &output).unwrap();
        assert!(output.join("fresh.bin").exists());
        assert!(!staging.exists());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn staging_dir_is_a_sibling_of_the_output_dir() {
        let staging = staging_dir_for(Path::new("/some/where/bins")).unwrap();
        assert_eq!(staging.parent(), Some(Path::new("/some/where")));
        assert!(staging
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".bins.staging-"));
    }

    /// A failed generation must not disturb pre-existing output contents.
    /// Uses an invalid proof count to trip the earliest failure path, and a
    /// crafted failure later via a file blocking the staging path.
    fn io_fail() -> std::io::Error {
        std::io::Error::other("injected rename failure")
    }

    /// Bugbot: a failed swap-in must never delete the staged artifacts while
    /// output_dir is empty. With a previous set present, roll it back and only
    /// then discard the (redundant) staged copy.
    #[test]
    fn failed_swap_in_restores_previous_artifacts() {
        let root = unique_tmp_dir("swap-rollback");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        let staging = staging_dir_for(&output).unwrap();
        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
        create_dir_all(&staging).unwrap();
        write(staging.join("fresh.bin"), b"fresh").unwrap();

        // Fail only the staging -> output rename; move-aside and rollback work.
        let staging_src = staging.clone();
        let err = commit_staging_dir_impl(&staging, &output, |src, dst| {
            if src == staging_src {
                Err(io_fail())
            } else {
                fs::rename(src, dst)
            }
        })
        .unwrap_err();

        assert!(format!("{err:#}").contains("previous artifacts were restored"));
        assert!(
            output.join("previous.bin").exists(),
            "previous artifact set must be rolled back into place"
        );
        assert!(!staging.exists(), "redundant staged copy is discarded");

        fs::remove_dir_all(&root).unwrap();
    }

    /// If the rollback fails too, BOTH copies must survive on disk and the
    /// error must say where they are.
    #[test]
    fn failed_swap_in_with_failed_rollback_preserves_both_copies() {
        let root = unique_tmp_dir("swap-rollback-fail");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        let staging = staging_dir_for(&output).unwrap();
        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
        create_dir_all(&staging).unwrap();
        write(staging.join("fresh.bin"), b"fresh").unwrap();

        // Fail every rename INTO output_dir: the swap-in and the rollback.
        let output_dst = output.clone();
        let err = commit_staging_dir_impl(&staging, &output, |src, dst| {
            if dst == output_dst {
                Err(io_fail())
            } else {
                fs::rename(src, dst)
            }
        })
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains("also failed"), "got: {msg}");
        assert!(
            staging.join("fresh.bin").exists(),
            "new artifacts must survive"
        );
        let old_path = staging.with_file_name({
            let mut n = staging.file_name().unwrap().to_os_string();
            n.push(".old");
            n
        });
        assert!(
            old_path.join("previous.bin").exists(),
            "previous artifacts must survive (moved aside)"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// With no previous output set, a failed swap-in must leave the staged
    /// directory (the only copy) on disk.
    #[test]
    fn failed_swap_in_without_previous_output_keeps_staging() {
        let root = unique_tmp_dir("swap-fresh-fail");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = staging_dir_for(&output).unwrap();
        create_dir_all(&staging).unwrap();
        write(staging.join("fresh.bin"), b"fresh").unwrap();

        let err = commit_staging_dir_impl(&staging, &output, |_, _| Err(io_fail())).unwrap_err();

        assert!(format!("{err:#}").contains("remain at"), "got: {err:#}");
        assert!(
            staging.join("fresh.bin").exists(),
            "only copy of the artifacts must not be deleted"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// A failed move-aside happens before anything moves: the previous set
    /// still serves from output_dir, so the staged copy is discarded.
    #[test]
    fn failed_move_aside_keeps_output_and_discards_staging() {
        let root = unique_tmp_dir("swap-aside-fail");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        let staging = staging_dir_for(&output).unwrap();
        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
        create_dir_all(&staging).unwrap();
        write(staging.join("fresh.bin"), b"fresh").unwrap();

        let output_src = output.clone();
        let err = commit_staging_dir_impl(&staging, &output, |src, dst| {
            if src == output_src {
                Err(io_fail())
            } else {
                fs::rename(src, dst)
            }
        })
        .unwrap_err();

        assert!(format!("{err:#}").contains("move previous"), "got: {err:#}");
        assert!(output.join("previous.bin").exists());
        assert!(!staging.exists());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn failed_generation_leaves_existing_output_untouched() {
        let root = unique_tmp_dir("gen-fail");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        create_dir_all(&output).unwrap();
        write(output.join("existing.bin"), b"keep me").unwrap();

        // Invalid count: fails validation before any staging.
        assert!(generate_all_circuit_binaries(&output, false, 0, None).is_err());
        assert!(output.join("existing.bin").exists());

        // Block staging-dir creation with a plain file at the staging path:
        // generation fails mid-stage, output must still be untouched and the
        // blocking file (not a dir) must not be swapped in.
        let staging = staging_dir_for(&output).unwrap();
        write(&staging, b"not a directory").unwrap();
        assert!(generate_all_circuit_binaries(&output, false, 1, None).is_err());
        assert!(output.join("existing.bin").exists());
        assert!(!output.join("common.bin").exists());

        fs::remove_dir_all(&root).unwrap();
    }
}
