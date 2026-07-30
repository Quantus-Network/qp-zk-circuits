//! Wormhole circuit artifact generation (leaf / private-batch / public-batch).
//!
//! # Trust boundary
//!
//! This crate is intended to run on a **trusted CI build host**. The checkout,
//! toolchain, and output parent during generation are not modeled as
//! adversarial. Local filesystem races against the publisher (symlink TOCTOU,
//! planted FIFOs, concurrent staging replacement, etc.) are **out of scope**;
//! see `wormhole/THREAT_MODEL.md`. Remaining in-scope obligations when these
//! artifacts are later loaded: no prover.bin, canonical verifier pinning,
//! and dummy-template validation.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use wormhole_aggregator::common::utils::commit_artifact_set;
use wormhole_aggregator::public_batch::circuit::generate_public_batch_circuit_binaries;

use plonky2::util::serialization::DefaultGateSerializer;
use wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::wormhole_leaf_circuit_config;

// Re-export CircuitBinsConfig from aggregator so users of circuit-builder can access it
pub use wormhole_aggregator::CircuitBinsConfig;

/// Generate only the leaf wormhole circuit binaries.
///
/// Low-level helper for partial regenerates. Prefer
/// [`generate_all_circuit_binaries`] for production builds (whole-directory
/// staging; see `wormhole/THREAT_MODEL.md`).
///
/// Note: no `prover.bin` is emitted. `WormholeProver` always builds the leaf
/// circuit from source so a poisoned prover artifact cannot exfiltrate
/// witness data through the proof's public-input list.
pub fn generate_circuit_binaries<P: AsRef<Path>>(output_dir: P) -> Result<()> {
    println!(
        "Building wormhole leaf circuit (non-ZK by design; ZK lives at the private-batch layer)..."
    );
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

    println!("Serializing circuit data...");

    let verifier_data = circuit_data.verifier_data();
    let common_data = &verifier_data.common;

    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize common data: {}", e))?;
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize verifier data: {}", e))?;

    println!(
        "Publishing {}/dummy_proof.bin ({} bytes)",
        output_path.display(),
        dummy_proof_bytes.len()
    );
    commit_artifact_set(
        output_path,
        &[
            ("dummy_proof.bin", dummy_proof_bytes),
            ("common.bin", common_bytes),
            ("verifier.bin", verifier_only_bytes),
        ],
        &[],
    )?;
    println!("Common data saved to {}/common.bin", output_path.display());
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
/// * `include_prover` - Whether to generate the dummy private-batch proof used for
///   public-batch padding (requires a private-batch proving run). No circuit emits a
///   prover binary: provers always rebuild their circuits from source (see
///   [`generate_circuit_binaries`])
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
    let staging_path = create_staging_dir(output_path)?;

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
                config.num_leaf_proofs,
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

/// Create a private staging directory next to `output_dir` (same filesystem
/// so the final `rename` is atomic), under an unpredictable name to avoid
/// colliding with a concurrent builder or leftover from a crashed run.
fn create_staging_dir(output_dir: &Path) -> Result<PathBuf> {
    let Some(name) = output_dir.file_name().and_then(|n| n.to_str()) else {
        bail!(
            "output dir {} has no usable directory name; pass an explicit directory path",
            output_dir.display()
        );
    };
    if let Some(parent) = output_dir.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create output parent directory {}",
                    parent.display()
                )
            })?;
        }
    }
    for _ in 0..8 {
        let candidate = output_dir.with_file_name(format!(
            ".{}.staging-{}-{:016x}",
            name,
            std::process::id(),
            rand::random::<u64>()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to create staging directory {}", candidate.display())
                })
            }
        }
    }
    bail!(
        "failed to create a fresh staging directory next to {}; \
         remove stale .{}.staging-* entries and retry",
        output_dir.display(),
        name
    );
}

/// Replace `output_dir` with the fully staged `staging_dir` via directory
/// renames. A pre-existing output dir is moved aside, then removed after the
/// swap. Whole-directory staging is operator hygiene against mixed leaf /
/// private-batch / public-batch generations — not a local-FS adversary
/// defense (see `wormhole/THREAT_MODEL.md`).
///
/// After a successful swap-in, failing to delete the moved-aside previous
/// copy is reported as a warning, not as command failure.
fn commit_staging_dir(staging_dir: &Path, output_dir: &Path) -> Result<()> {
    commit_staging_dir_impl(staging_dir, output_dir, |src, dst| fs::rename(src, dst))
}

/// [`commit_staging_dir`] with an injectable rename for rollback tests.
fn commit_staging_dir_impl(
    staging_dir: &Path,
    output_dir: &Path,
    rename: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    if !staging_dir.is_dir() {
        bail!(
            "staged artifact path {} is not a directory; refusing to publish",
            staging_dir.display()
        );
    }

    let mut old_name = staging_dir.file_name().unwrap_or_default().to_os_string();
    old_name.push(".old");
    let old_path = staging_dir.with_file_name(old_name);
    let previous_exists = output_dir.exists();
    if previous_exists {
        if !output_dir.is_dir() {
            let _ = fs::remove_dir_all(staging_dir);
            bail!(
                "output path {} exists but is not a directory; remove or rename it and retry",
                output_dir.display()
            );
        }
        if let Err(e) = rename(output_dir, &old_path) {
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
        if previous_exists {
            match rename(&old_path, output_dir) {
                Ok(()) => {
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
        if let Err(e) = fs::remove_dir_all(&old_path) {
            eprintln!(
                "warning: published artifacts to {}, but failed to remove the previous \
                 artifact copy at {}: {e}; remove it manually if it is no longer needed",
                output_dir.display(),
                old_path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::write;

    fn unique_tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "qp-circuit-builder-test-{}-{}",
            tag,
            std::process::id()
        ))
    }

    /// `--output` must be a directory; a file at that path is rejected before
    /// the swap (operator hygiene, not local-FS adversary defense).
    #[test]
    fn commit_rejects_non_directory_previous_output() {
        let root = unique_tmp_dir("commit-not-dir");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = create_staging_dir(&output).unwrap();

        write(&output, b"i am a file").unwrap();
        write(staging.join("fresh.bin"), b"new artifact").unwrap();

        let err = commit_staging_dir(&staging, &output).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a directory"),
            "got: {err:#}"
        );
        assert_eq!(
            fs::read(&output).unwrap(),
            b"i am a file",
            "previous non-directory must be left untouched"
        );
        assert!(
            !staging.exists(),
            "rejected commit discards the (uncommitted) staged copy"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// After the staged directory is renamed into place the publish has
    /// succeeded. An undeletable moved-aside previous copy must not flip the
    /// result to Err — CI/operators keying off the exit code would otherwise
    /// treat a live artifact update as a failed run (audit finding).
    #[cfg(unix)]
    #[test]
    fn successful_publish_is_not_failed_by_old_copy_cleanup() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_tmp_dir("commit-cleanup-best-effort");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = create_staging_dir(&output).unwrap();

        create_dir_all(&output).unwrap();
        write(output.join("stale.bin"), b"old artifact").unwrap();
        // Nested dir without write permission: remove_dir_all cannot unlink
        // its children once this tree is the moved-aside `.old` copy.
        let locked = output.join("locked");
        create_dir_all(&locked).unwrap();
        write(locked.join("x.bin"), b"x").unwrap();
        let mut perms = fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o555);
        fs::set_permissions(&locked, perms).unwrap();

        write(staging.join("fresh.bin"), b"new artifact").unwrap();

        let result = commit_staging_dir(&staging, &output);
        assert!(
            result.is_ok(),
            "publish must report success even when old-copy cleanup fails: {result:?}"
        );
        assert!(
            output.join("fresh.bin").exists(),
            "new artifacts must be live at output_dir"
        );
        assert!(
            !output.join("stale.bin").exists(),
            "stale contents must not remain in the published dir"
        );

        // Make any leftover `.old` tree deletable so the test cleans up.
        for entry in fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.ends_with(".old") {
                continue;
            }
            let locked_old = path.join("locked");
            if locked_old.exists() {
                let mut p = fs::metadata(&locked_old).unwrap().permissions();
                p.set_mode(0o755);
                fs::set_permissions(&locked_old, p).unwrap();
            }
        }

        fs::remove_dir_all(&root).unwrap();
    }

    /// The swap must replace stale contents wholesale, not merge into them.
    #[test]
    fn commit_replaces_existing_output_dir_wholesale() {
        let root = unique_tmp_dir("commit-replace");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = create_staging_dir(&output).unwrap();

        create_dir_all(&output).unwrap();
        write(output.join("stale.bin"), b"old artifact").unwrap();
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
        let staging = create_staging_dir(&output).unwrap();

        write(staging.join("fresh.bin"), b"new artifact").unwrap();

        commit_staging_dir(&staging, &output).unwrap();
        assert!(output.join("fresh.bin").exists());
        assert!(!staging.exists());

        fs::remove_dir_all(&root).unwrap();
    }

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
        let staging = create_staging_dir(&output).unwrap();
        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
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
        let staging = create_staging_dir(&output).unwrap();
        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
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
        let staging = create_staging_dir(&output).unwrap();
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
        let staging = create_staging_dir(&output).unwrap();
        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
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

    /// A failed generation must not disturb pre-existing output contents.
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

        fs::remove_dir_all(&root).unwrap();
    }

    /// If the staging directory cannot be created at all, generation must fail
    /// before any circuit work begins and leave existing output untouched.
    #[cfg(unix)]
    #[test]
    fn unwritable_parent_fails_before_building_and_leaves_output_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_tmp_dir("gen-parent-ro");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        create_dir_all(&output).unwrap();
        write(output.join("existing.bin"), b"keep me").unwrap();

        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
        // Running as root bypasses permission bits; nothing to exercise then.
        if fs::create_dir(root.join(".probe")).is_ok() {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            fs::remove_dir_all(&root).unwrap();
            return;
        }

        let result = generate_all_circuit_binaries(&output, false, 1, None);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("staging directory"),
            "got: {err:#}"
        );
        assert!(output.join("existing.bin").exists());
        assert!(!output.join("common.bin").exists());

        fs::remove_dir_all(&root).unwrap();
    }
}
