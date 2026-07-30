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
/// This is a low-level helper for partial artifact generation. For the full flow that also
/// emits `config.json`, use [`generate_all_circuit_binaries`].
///
/// The three leaf files are published all-or-nothing through the aggregator's
/// `commit_artifact_set` (exclusive-create staging plus rename into place), so
/// a failed re-run never leaves a mixed leaf set and a symlink pre-planted at
/// an artifact filename is replaced rather than followed. Whole-directory
/// consistency across all stages is still only guaranteed by
/// [`generate_all_circuit_binaries`]; prefer it unless you are deliberately
/// regenerating one stage into an existing set.
///
/// Note: no `prover.bin` is emitted for the leaf circuit. `WormholeProver` always builds
/// the (small, fast-to-build) leaf circuit from source; loading prover-only artifacts was
/// removed because a poisoned artifact could exfiltrate private witness data through the
/// proof's public-input list.
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
    // A previous publish hard-killed mid-swap leaves orphaned temp/backup
    // entries behind; we are about to replace the set, so sweep them now.
    wormhole_aggregator::common::utils::sweep_stale_artifact_droppings(output_path)?;

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

/// Create the private staging directory that artifact generation writes into:
/// a sibling of `output_dir` (same filesystem, so the final `rename` is
/// atomic), created exclusively under an unpredictable name.
///
/// Exclusive `create_dir` (create-new semantics) is the symlink-safety
/// guarantee: `mkdir` refuses to follow a symlink at the final component and
/// fails if anything already exists at the path, so a local attacker with
/// write access to the output parent can never get a pre-planted symlink (or
/// a directory seeded with artifact-name symlinks) adopted as the staging
/// dir and redirect the builder's `std::fs::write` calls onto arbitrary
/// files. The random suffix makes the path unpredictable, so a planted entry
/// cannot even force an error, and the pid keeps stale leftovers attributable.
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
    // A few attempts are plenty: a collision requires an identical 64-bit
    // random suffix to appear in the same parent under the same pid.
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

/// Identity of a plain directory we intend to publish, captured via
/// `symlink_metadata` so a symlink-at-that-path never counts as a directory.
/// On Unix we also pin `(dev, ino)` so a TOCTOU replacement of the staging
/// path with a different directory (or symlink) between the check and
/// `rename` is detectable after publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlainDirId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

fn plain_dir_id(path: &Path) -> Result<PlainDirId> {
    let meta = fs::symlink_metadata(path).with_context(|| {
        format!("failed to inspect artifact path {}", path.display())
    })?;
    // `symlink_metadata` + `is_dir` rejects symlinks even when their target
    // is a directory — that is the whole point of the staging-path check.
    if !meta.is_dir() {
        bail!(
            "artifact path {} is not a plain directory (symlink or file)",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(PlainDirId {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Ok(PlainDirId {})
    }
}

/// Remove a just-published path that failed the post-rename identity check.
/// It may be a symlink (the TOCTOU attack), a file, or a wrong directory.
fn remove_bad_publish_path(path: &Path) -> std::io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() || meta.is_file() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    }
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
///
/// After the staged directory has been renamed into `output_dir`, the publish
/// has succeeded: failing to delete the moved-aside previous copy is reported
/// as a warning, not as command failure. Conflating that cleanup with publish
/// success made automation treat a live, complete artifact update as a failed
/// run (false rollback / retry / alert) whenever the old path was not a
/// recursively-removable directory (audit finding).
///
/// Symlink / inode TOCTOU: a single `symlink_metadata` check before `rename`
/// is not atomic with the rename's pathname lookup. A local attacker who can
/// write the output parent could replace the staging directory with a symlink
/// after the check and have that symlink published as `output_dir` while the
/// previous artifact set is deleted. We pin the staging directory's identity,
/// re-validate it immediately before the rename, and require the same identity
/// at `output_dir` afterward — rolling back (and refusing success) on mismatch
/// (audit finding).
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
    // Pin the staging directory's identity up front. Renaming a symlink into
    // place would hand out an artifact dir whose contents remain mutable by
    // whoever owns the link target.
    let staging_id = plain_dir_id(staging_dir).with_context(|| {
        format!(
            "staged artifact path {} is not a plain directory; \
             refusing to publish it as the artifact dir",
            staging_dir.display()
        )
    })?;

    let mut old_name = staging_dir.file_name().unwrap_or_default().to_os_string();
    old_name.push(".old");
    let old_path = staging_dir.with_file_name(old_name);
    let previous_exists = output_dir.exists();
    if previous_exists {
        // Refuse to treat a file or symlink as the previous artifact set:
        // `--output` is a directory, and moving a non-directory aside would
        // leave `remove_dir_all` unable to clean it up after a successful
        // publish (the exact cleanup/success conflation this function avoids).
        if let Err(e) = plain_dir_id(output_dir) {
            let _ = fs::remove_dir_all(staging_dir);
            return Err(e).context(format!(
                "output path {} exists but is not a plain directory (symlink or file); \
                 refusing to treat it as the previous artifact set — remove or rename \
                 it and retry",
                output_dir.display()
            ));
        }

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

    // Re-validate immediately before the rename's pathname lookup. Still not
    // fully atomic with the rename, but shrinks the race; the post-rename
    // identity check below is what makes a won race fail closed.
    let staging_id_pre_rename = plain_dir_id(staging_dir).with_context(|| {
        format!(
            "staged artifact path {} was replaced after the initial check \
             (no longer a plain directory); refusing to publish",
            staging_dir.display()
        )
    })?;
    if staging_id_pre_rename != staging_id {
        // A different directory now sits at the staging path. Do not publish
        // it; restore any moved-aside previous set first.
        if previous_exists {
            let _ = rename(&old_path, output_dir);
        }
        let _ = fs::remove_dir_all(staging_dir);
        bail!(
            "staged artifact path {} was replaced with a different directory \
             before publish; refusing to publish attacker-controlled contents",
            staging_dir.display()
        );
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

    // Close the check-then-rename TOCTOU: the path published at output_dir
    // must be the same plain directory inode we staged. If an attacker swapped
    // in a symlink (or another directory) between the pre-rename check and
    // rename's lookup, detect it here and roll back before declaring success
    // or deleting the previous artifact set.
    match plain_dir_id(output_dir) {
        Ok(published_id) if published_id == staging_id => {}
        Ok(_) | Err(_) => {
            let _ = remove_bad_publish_path(output_dir);
            if previous_exists {
                match rename(&old_path, output_dir) {
                    Ok(()) => {
                        bail!(
                            "published path {} was not the staged artifact directory \
                             (replaced by a symlink or different directory during \
                             rename); previous artifacts were restored",
                            output_dir.display()
                        );
                    }
                    Err(rollback_err) => {
                        bail!(
                            "published path {} was not the staged artifact directory \
                             (replaced during rename), and restoring the previous \
                             artifacts also failed ({}); previous artifacts remain at {}",
                            output_dir.display(),
                            rollback_err,
                            old_path.display()
                        );
                    }
                }
            }
            bail!(
                "published path {} was not the staged artifact directory \
                 (replaced by a symlink or different directory during rename); \
                 refusing to treat the publish as successful",
                output_dir.display()
            );
        }
    }

    if previous_exists {
        // The new set is already live at output_dir. Cleanup of the moved-aside
        // previous copy must not flip the command to failure: operators and CI
        // that key off the exit code would otherwise rerun expensive generation
        // or roll back despite a successful publish (audit finding).
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

    /// `--output` is a directory. A file (or symlink) planted at that path
    /// must be rejected before the swap, not moved aside and then left as a
    /// non-directory `.old` that `remove_dir_all` cannot clean (audit finding).
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
            format!("{err:#}").contains("not a plain directory"),
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

    /// Staging paths must be minted fresh on every call (exclusive creation
    /// under an unpredictable name), never re-derived from the pid alone: a
    /// predictable path is what lets a local attacker pre-create it.
    #[test]
    fn create_staging_dir_mints_a_fresh_unique_directory_per_call() {
        let root = unique_tmp_dir("staging-fresh");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");

        let a = create_staging_dir(&output).unwrap();
        let b = create_staging_dir(&output).unwrap();
        assert_ne!(
            a, b,
            "staging paths must be unique per call, not a pid-only derivation"
        );
        for dir in [&a, &b] {
            let meta = fs::symlink_metadata(dir).unwrap();
            assert!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "staging path must be a freshly created real directory"
            );
            assert_eq!(
                dir.parent(),
                Some(root.as_path()),
                "staging dir must stay a sibling of the output dir"
            );
            assert!(dir
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(".bins.staging-"));
        }

        fs::remove_dir_all(&root).unwrap();
    }

    /// A local attacker with write access to the output parent plants a
    /// symlink at the predictable staging path. The builder must not adopt it:
    /// artifact writes would land in attacker-controlled storage.
    #[cfg(unix)]
    #[test]
    fn create_staging_dir_does_not_adopt_a_planted_symlink() {
        let root = unique_tmp_dir("staging-symlink");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let attacker_target = root.join("attacker-target");
        create_dir_all(&attacker_target).unwrap();

        // The historical (predictable) staging name: .<name>.staging-<pid>.
        let planted = output.with_file_name(format!(".bins.staging-{}", std::process::id()));
        std::os::unix::fs::symlink(&attacker_target, &planted).unwrap();

        let staging = create_staging_dir(&output).unwrap();
        let meta = fs::symlink_metadata(&staging).unwrap();
        assert!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "staging dir must be a freshly created real directory, not the planted symlink"
        );
        write(staging.join("probe.bin"), b"artifact").unwrap();
        assert!(
            !attacker_target.join("probe.bin").exists(),
            "artifact writes must not land in attacker-controlled storage"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// The commit phase must refuse to publish a staging path that is not a
    /// plain directory: renaming a symlink into place would hand out an
    /// artifact dir whose contents remain attacker-mutable.
    #[cfg(unix)]
    #[test]
    fn commit_refuses_to_publish_a_symlinked_staging_dir() {
        let root = unique_tmp_dir("commit-symlink");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let attacker_target = root.join("attacker-target");
        create_dir_all(&attacker_target).unwrap();
        write(attacker_target.join("fresh.bin"), b"attacker mutable").unwrap();
        let staging = root.join(".bins.staging-evil");
        std::os::unix::fs::symlink(&attacker_target, &staging).unwrap();

        let err = commit_staging_dir(&staging, &output).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a plain directory"),
            "got: {err:#}"
        );
        assert!(
            fs::symlink_metadata(&output).is_err(),
            "a symlinked staging path must never be published as the artifact dir"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// TOCTOU (audit finding): the pre-rename plain-directory check and the
    /// `rename` pathname lookup are separate. A local attacker who replaces
    /// the staging directory with a symlink in that window must not get a
    /// successful publish that leaves `--output` as attacker-mutable storage
    /// while the previous artifact set is deleted. The post-rename inode /
    /// type check must fail closed and restore the previous set.
    #[cfg(unix)]
    #[test]
    fn commit_rolls_back_if_staging_replaced_by_symlink_during_rename() {
        let root = unique_tmp_dir("commit-toctou-symlink");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = create_staging_dir(&output).unwrap();

        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
        write(staging.join("fresh.bin"), b"fresh").unwrap();

        let attacker_target = root.join("attacker-target");
        create_dir_all(&attacker_target).unwrap();
        write(attacker_target.join("evil.bin"), b"attacker mutable").unwrap();

        let staging_src = staging.clone();
        let attacker = attacker_target.clone();
        let err = commit_staging_dir_impl(&staging, &output, |src, dst| {
            if src == staging_src {
                // Win the race at rename time: drop our staging dir and plant
                // a symlink under the same path, then rename that symlink.
                let _ = fs::remove_dir_all(src);
                std::os::unix::fs::symlink(&attacker, src)?;
                fs::rename(src, dst)
            } else {
                fs::rename(src, dst)
            }
        })
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("not the staged artifact directory")
                || msg.contains("previous artifacts were restored"),
            "got: {msg}"
        );
        assert!(
            output.join("previous.bin").exists(),
            "previous artifact set must be restored after a TOCTOU publish attempt"
        );
        assert!(
            !output.join("evil.bin").exists(),
            "attacker-controlled contents must not remain published at output_dir"
        );
        let out_meta = fs::symlink_metadata(&output).unwrap();
        assert!(
            out_meta.is_dir() && !out_meta.file_type().is_symlink(),
            "output_dir must be a plain directory again after rollback"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// Same TOCTOU window, but the replacement is a different plain directory
    /// (different inode). Publishing it would still hand the attacker a
    /// successful exit with contents they control; the inode pin must reject it.
    #[cfg(unix)]
    #[test]
    fn commit_rolls_back_if_staging_replaced_by_different_directory_during_rename() {
        let root = unique_tmp_dir("commit-toctou-dir");
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();
        let output = root.join("bins");
        let staging = create_staging_dir(&output).unwrap();

        create_dir_all(&output).unwrap();
        write(output.join("previous.bin"), b"previous").unwrap();
        write(staging.join("fresh.bin"), b"fresh").unwrap();

        let attacker_dir = root.join("attacker-dir");
        create_dir_all(&attacker_dir).unwrap();
        write(attacker_dir.join("evil.bin"), b"attacker mutable").unwrap();

        let staging_src = staging.clone();
        let attacker = attacker_dir.clone();
        let err = commit_staging_dir_impl(&staging, &output, |src, dst| {
            if src == staging_src {
                let _ = fs::remove_dir_all(src);
                // Move the attacker's directory onto the staging path (same
                // parent, so rename is atomic) then publish that inode.
                fs::rename(&attacker, src)?;
                fs::rename(src, dst)
            } else {
                fs::rename(src, dst)
            }
        })
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("not the staged artifact directory"),
            "got: {err:#}"
        );
        assert!(
            output.join("previous.bin").exists(),
            "previous artifact set must be restored"
        );
        assert!(
            !output.join("evil.bin").exists(),
            "attacker directory must not remain published"
        );

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

    /// A symlink pre-planted at an artifact filename must not redirect the
    /// write onto its target: `std::fs::write` follows symlinks and truncates,
    /// so an attacker with write access to the output directory could make the
    /// builder clobber any file writable by the invoking account (audit
    /// finding: symlink-following artifact writes). Publishing must replace
    /// the planted entry itself and leave the victim untouched.
    #[cfg(unix)]
    #[test]
    fn leaf_artifact_writes_do_not_follow_planted_symlinks() {
        let root = unique_tmp_dir("symlink-clobber");
        let _ = fs::remove_dir_all(&root);
        let output = root.join("bins");
        create_dir_all(&output).unwrap();

        let victim = root.join("victim.txt");
        write(&victim, b"precious data").unwrap();
        std::os::unix::fs::symlink(&victim, output.join("common.bin")).unwrap();

        let result = generate_circuit_binaries(&output);

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"precious data",
            "artifact publication must never write through a planted symlink"
        );
        if result.is_ok() {
            let common = fs::read(output.join("common.bin")).unwrap();
            assert_ne!(
                common, b"precious data",
                "a successful run must have replaced the planted entry with a real artifact"
            );
        }

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
