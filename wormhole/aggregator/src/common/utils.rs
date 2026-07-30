#[cfg(feature = "std")]
use anyhow::Context;
use anyhow::{anyhow, bail, Result};
use plonky2::{
    field::types::PrimeField64,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
        },
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    util::serialization::DefaultGateSerializer,
};
use qp_wormhole_inputs::validate_proof_count;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::{
    wormhole_leaf_circuit_config, wormhole_private_batch_circuit_config,
    wormhole_public_batch_circuit_config, C, D, F,
};

use crate::private_batch::circuit::{
    circuit_logic::PrivateBatchCircuit,
    constants::{aggregated_output, ASSET_ID_START, LEAF_PI_LEN},
};
use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;

/// Maximum size accepted for any serialized circuit-artifact file.
///
/// The largest legitimate artifact is a serialized recursive proof (hundreds
/// of KB); common/verifier data is smaller still. 64 MiB gives generous
/// headroom for config variations while bounding the allocation an untrusted
/// artifact directory can force: without a cap, a single oversized or sparse
/// `*.bin` file is read fully into memory BEFORE canonical validation gets a
/// chance to reject it, letting an attacker-chosen directory crash or memory-
/// starve the loading process.
pub const MAX_ARTIFACT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Read a circuit-artifact file, refusing anything larger than
/// [`MAX_ARTIFACT_FILE_BYTES`] before allocating for its contents.
///
/// Only regular files are accepted. A FIFO, device node, or symlink to one
/// planted at an artifact path would otherwise block `open` (a FIFO with no
/// writer) or `read_to_end` (a stream that never reaches EOF) forever,
/// independent of the size cap below. On unix the open uses `O_NONBLOCK` so
/// even the FIFO-open case cannot stall; the file type is then checked via
/// `fstat` on the opened handle before any read. `O_NONBLOCK` has no effect
/// on regular-file opens or reads.
///
/// The size is checked via `fstat` on the already-opened handle (no
/// stat-then-open race), and the read itself is additionally capped with
/// `Read::take` in case the file grows after the check.
#[cfg(feature = "std")]
pub fn read_artifact_file(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let mut options = std::fs::File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open artifact file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to stat artifact file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "artifact file {} is not a regular file; refusing to load it",
            path.display()
        );
    }
    let claimed_len = metadata.len();
    if claimed_len > MAX_ARTIFACT_FILE_BYTES {
        bail!(
            "artifact file {} is {} bytes, which exceeds the {} byte limit for \
             circuit artifacts; refusing to load it",
            path.display(),
            claimed_len,
            MAX_ARTIFACT_FILE_BYTES
        );
    }

    let mut bytes = Vec::with_capacity(claimed_len as usize);
    file.take(MAX_ARTIFACT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read artifact file {}", path.display()))?;
    if bytes.len() as u64 > MAX_ARTIFACT_FILE_BYTES {
        bail!(
            "artifact file {} grew past the {} byte limit for circuit artifacts \
             while being read; refusing to load it",
            path.display(),
            MAX_ARTIFACT_FILE_BYTES
        );
    }
    Ok(bytes)
}

/// Reject any artifact name that is not a single basename confined under
/// `bins_dir`.
///
/// `commit_artifact_set` builds staging, backup, and final paths with
/// `bins_dir.join(name)` (and `bins_dir.join(format!(".{name}.…"))`). A name
/// carrying directory components, `..`, or an absolute path would therefore
/// resolve outside `bins_dir`. This is an allowlist — the name must already
/// be exactly one normal path component — not a scrubber that tries to strip
/// hostile fragments.
#[cfg(feature = "std")]
fn ensure_artifact_basename(name: &str) -> Result<()> {
    use std::path::Path;

    let path = Path::new(name);
    let Some(file_name) = path.file_name() else {
        bail!("artifact name {name:?} is not a valid basename");
    };
    // Equality holds iff `name` is a single component: `file_name()` strips
    // parents / trailing separators, so `../x`, `a/b`, `/abs`, `.`, and `..`
    // all fail. Platform separators (`\` on Windows) are handled by Path.
    if path.as_os_str() != file_name {
        bail!(
            "artifact name {name:?} must be a single filename with no directory components"
        );
    }
    // NUL can truncate C-style path APIs on some platforms; refuse it even
    // though it is not a Path separator.
    if name.contains('\0') {
        bail!("artifact name must not contain NUL");
    }
    Ok(())
}

/// Publish a matched set of artifact files into `bins_dir` all-or-nothing,
/// optionally removing stale files that are no longer part of the set.
///
/// Artifact files are consumed as matched sets (loaders pin them against a
/// canonical circuit rebuild and verify templates against the loaded verifier
/// data), so a directory holding a fresh file from one generation beside a
/// stale file from another is rejected until regenerated. Naive in-place
/// writes create exactly that state whenever a re-run fails between files.
///
/// Instead, every file is first staged under a fresh unpredictable temp name
/// in the same directory (exclusive create, so a pre-planted entry or symlink
/// is never adopted), and only after all stages succeed are the previous
/// artifacts (including any `remove_stale` entries) moved aside and the
/// staged files renamed into place. Any HANDLED failure rolls the moved-aside
/// originals back, so an error return always leaves either the complete
/// previous set or the complete new set — never a mix. The unwritten window
/// shrinks from the whole multi-minute build-and-write to the instants
/// between renames of already-complete files.
///
/// A hard crash (SIGKILL, power loss) inside that window is NOT rolled back:
/// dying between the move-aside loop and the rename-in loop leaves the
/// directory with no live artifacts plus orphaned `.<name>.old-<pid>-<rand>`
/// (and possibly `.<name>.tmp-<pid>-<rand>`) entries. That state is
/// fail-closed — loaders see missing artifacts, never a mixed generation —
/// but it needs regeneration to recover. The builder entry points call
/// [`sweep_stale_artifact_droppings`] before regenerating so those orphans do
/// not accumulate. For whole-directory consistency across all stages, the
/// staging-directory swap in `circuit-builder`'s
/// `generate_all_circuit_binaries` remains the only true whole-set atomic
/// primitive.
///
/// Because staging opens with create-new semantics and publication renames
/// over the final name, a symlink pre-planted at an artifact filename is
/// replaced as an entry rather than followed, so a write can never be
/// redirected onto the symlink's target. Artifact names (both published and
/// `remove_stale`) must be basenames with no directory components, so path
/// construction cannot escape `bins_dir`. Public so `circuit-builder` can
/// publish the leaf artifact set through the same path.
#[cfg(feature = "std")]
pub fn commit_artifact_set(
    bins_dir: &std::path::Path,
    files: &[(&str, Vec<u8>)],
    remove_stale: &[&str],
) -> Result<()> {
    use std::fs;
    use std::io::Write as _;

    // Validate before any filesystem work so a hostile name cannot stage,
    // move aside, or delete outside `bins_dir`.
    for name in files
        .iter()
        .map(|(name, _)| *name)
        .chain(remove_stale.iter().copied())
    {
        ensure_artifact_basename(name)?;
    }

    let unique = format!("{}-{:016x}", std::process::id(), rand::random::<u64>());
    let tmp_path = |name: &str| bins_dir.join(format!(".{name}.tmp-{unique}"));
    let old_path = |name: &str| bins_dir.join(format!(".{name}.old-{unique}"));
    let all_names = || {
        files
            .iter()
            .map(|(name, _)| *name)
            .chain(remove_stale.iter().copied())
    };

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

    // Phase 2: move previous artifacts (and stale files) aside, then swap the
    // staged set in.
    let mut moved_aside: Vec<&str> = Vec::new();
    let mut swapped: Vec<&str> = Vec::new();
    let swap_result = (|| -> Result<()> {
        for name in all_names() {
            match fs::rename(bins_dir.join(name), old_path(name)) {
                Ok(()) => moved_aside.push(name),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "Failed to move previous {} aside",
                            bins_dir.join(name).display()
                        )
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
            // The new set is committed; the moved-aside copies (and moved-aside
            // stale files) are redundant.
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
            for name in all_names() {
                let final_path = bins_dir.join(name);
                if moved_aside.contains(&name) {
                    if fs::rename(old_path(name), &final_path).is_err() {
                        // A blocking entry (e.g. an already-swapped file under
                        // a directory-shaped old copy) must not strand the
                        // rollback in a mixed state.
                        let _ = fs::remove_file(&final_path);
                        let _ = fs::rename(old_path(name), &final_path);
                    }
                } else if swapped.contains(&name) {
                    let _ = fs::remove_file(&final_path);
                }
                let _ = fs::remove_file(tmp_path(name));
            }
            Err(e)
        }
    }
}

/// Remove orphaned `commit_artifact_set` droppings from `bins_dir`.
///
/// A publish hard-killed mid-swap (SIGKILL, power loss) leaves behind
/// `.<name>.tmp-<pid>-<rand>` staged files and/or `.<name>.old-<pid>-<rand>`
/// moved-aside originals that no later run adopts (the random suffix is fresh
/// per call). This sweep deletes exactly those patterns: a leading dot, a
/// `.tmp-`/`.old-` marker, and the `<pid>-<16 hex>` suffix `commit_artifact_set`
/// generates. Unrelated dotfiles are left alone.
///
/// Only called from the builder entry points, immediately before
/// regeneration: on the read/prove paths a sweep could race a concurrent
/// publisher and delete its in-flight staging files, but a builder is about
/// to replace the whole set anyway. Returns the number of entries removed.
#[cfg(feature = "std")]
pub fn sweep_stale_artifact_droppings(bins_dir: &std::path::Path) -> Result<usize> {
    use std::fs;

    fn is_dropping(name: &str) -> bool {
        if !name.starts_with('.') {
            return false;
        }
        let Some(idx) = name.rfind(".tmp-").or_else(|| name.rfind(".old-")) else {
            return false;
        };
        // Suffix shape from commit_artifact_set: "<pid>-<16 lowercase hex>".
        let suffix = &name[idx + ".tmp-".len()..];
        let Some((pid, rand)) = suffix.split_once('-') else {
            return false;
        };
        !pid.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && rand.len() == 16
            && rand.bytes().all(|b| b.is_ascii_hexdigit())
    }

    let entries = match fs::read_dir(bins_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("Failed to list {}", bins_dir.display())),
    };

    let mut removed = 0usize;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_dropping(name) {
            continue;
        }
        let path = entry.path();
        // Moved-aside entries can be directory-shaped (a planted directory
        // that a previous publish moved aside), so fall back accordingly.
        let dir_fallback = match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(_) => fs::remove_dir_all(&path),
        };
        if !path.exists() {
            removed += 1;
        } else if let Err(e) = dir_fallback {
            // Don't fail the rebuild over an unremovable dropping, but don't
            // let the accumulation this sweep exists to prevent silently
            // resume either.
            eprintln!(
                "warning: failed to remove orphaned artifact dropping {}: {e}",
                path.display()
            );
        }
    }
    if removed > 0 {
        println!(
            "Removed {removed} orphaned staging/backup entries from {} (leftovers of an interrupted artifact publish)",
            bins_dir.display()
        );
    }
    Ok(removed)
}

/// Load verifier circuit data (common + verifier-only) from serialized bytes.
///
/// Prefer [`load_canonical_leaf_verifier_data`] /
/// [`load_canonical_private_batch_verifier_data`] for untrusted artifacts: those
/// pin by raw byte equality against a canonical rebuild and never ask Plonky2
/// to deserialize attacker-controlled length fields.
pub fn load_verifier_data_from_bytes(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    label: &str,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
        .map_err(|e| anyhow!("failed to deserialize {} common data: {}", label, e))?;

    let verifier_only =
        VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes.to_vec())
            .map_err(|e| anyhow!("failed to deserialize {} verifier-only data: {}", label, e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
}

/// Pin untrusted common/verifier-only artifact bytes to a canonical rebuild by
/// raw equality. Never deserializes the untrusted side: Plonky2's
/// `CommonCircuitData::from_bytes` reserves vector capacities from length
/// fields in the artifact before those lengths are proven consistent with the
/// file, so a capped-but-poisoned buffer can force large transient allocations
/// (or allocator failure) before any canonical check runs.
fn ensure_artifact_bytes_match_canonical(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    canonical: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<()> {
    let gate_serializer = DefaultGateSerializer;
    let canonical_common = canonical
        .common
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize canonical {} common data: {}", label, e))?;
    if common_bytes != canonical_common.as_slice() {
        bail!(
            "loaded {} common circuit data does not match the canonical circuit",
            label
        );
    }

    let canonical_vo = canonical.verifier_only.to_bytes().map_err(|e| {
        anyhow!(
            "failed to serialize canonical {} verifier-only data: {}",
            label,
            e
        )
    })?;
    if verifier_only_bytes != canonical_vo.as_slice() {
        bail!(
            "loaded {} verifier-only data does not match the canonical circuit",
            label
        );
    }
    Ok(())
}

/// Load leaf verifier data and reject anything that is not the canonical Wormhole leaf circuit.
pub fn load_canonical_leaf_verifier_data(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
) -> Result<VerifierCircuitData<F, C, D>> {
    let canonical = canonical_leaf_verifier_data();
    ensure_artifact_bytes_match_canonical(common_bytes, verifier_only_bytes, &canonical, "leaf")?;
    Ok(canonical)
}

/// Load private-batch verifier data pinned to the canonical private-batch circuit for
/// `num_leaf_proofs`. `leaf` must be canonical leaf verifier data (loaded pinned or rebuilt).
///
/// The untrusted artifact bytes are compared to the canonical serialization
/// without deserializing them — see [`ensure_artifact_bytes_match_canonical`].
pub fn load_canonical_private_batch_verifier_data(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    let canonical = canonical_private_batch_verifier_data(leaf, num_leaf_proofs)?;
    ensure_artifact_bytes_match_canonical(
        common_bytes,
        verifier_only_bytes,
        &canonical,
        "private_batch",
    )?;
    Ok(canonical)
}

pub fn ensure_common_matches_canonical(
    loaded: &CommonCircuitData<F, D>,
    canonical: &CommonCircuitData<F, D>,
    label: &str,
) -> Result<()> {
    ensure_config_is_canonical(&loaded.config, &canonical.config, label)?;

    let gate_serializer = DefaultGateSerializer;
    let loaded_bytes = loaded
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize loaded {} common data: {}", label, e))?;
    let canonical_bytes = canonical
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize canonical {} common data: {}", label, e))?;

    if loaded_bytes != canonical_bytes {
        bail!(
            "loaded {} common circuit data does not match the canonical circuit",
            label
        );
    }

    Ok(())
}

pub fn ensure_verifier_data_matches_canonical(
    loaded: &VerifierCircuitData<F, C, D>,
    canonical: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<()> {
    ensure_common_matches_canonical(&loaded.common, &canonical.common, label)?;

    let loaded_vo = loaded.verifier_only.to_bytes().map_err(|e| {
        anyhow!(
            "failed to serialize loaded {} verifier-only data: {}",
            label,
            e
        )
    })?;
    let canonical_vo = canonical.verifier_only.to_bytes().map_err(|e| {
        anyhow!(
            "failed to serialize canonical {} verifier-only data: {}",
            label,
            e
        )
    })?;

    if loaded_vo != canonical_vo {
        bail!(
            "loaded {} verifier-only data does not match the canonical circuit",
            label
        );
    }

    Ok(())
}

pub fn ensure_config_is_canonical(
    loaded: &CircuitConfig,
    expected: &CircuitConfig,
    label: &str,
) -> Result<()> {
    if loaded != expected {
        bail!(
            "loaded {} circuit config does not match the canonical Wormhole config \
             (security_bits loaded={}, expected={})",
            label,
            loaded.security_bits,
            expected.security_bits
        );
    }
    Ok(())
}

pub fn canonical_leaf_verifier_data() -> VerifierCircuitData<F, C, D> {
    WormholeCircuit::new(wormhole_leaf_circuit_config()).build_verifier()
}

pub fn canonical_private_batch_verifier_data(
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    Ok(PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf.common,
        &leaf.verifier_only,
        num_leaf_proofs,
    )?
    .build_verifier())
}

pub fn canonical_public_batch_verifier_data(
    private_batch: &VerifierCircuitData<F, C, D>,
    num_private_batch_proofs: usize,
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    Ok(PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private_batch.common.clone(),
        &private_batch.verifier_only,
        num_private_batch_proofs,
        num_leaf_proofs,
    )?
    .build_verifier())
}

fn ensure_len_matches(
    actual: usize,
    expected: usize,
    label: &str,
    slot: usize,
    what: &str,
) -> Result<()> {
    if actual != expected {
        bail!(
            "{} at slot {} is malformed: {} has length {}, but the circuit expects {}",
            label,
            slot,
            what,
            actual,
            expected
        );
    }
    Ok(())
}

/// Preflight a caller-supplied proof's full internal shape against the
/// circuit's proof targets, so a malformed proof is rejected at a Result
/// boundary instead of reaching plonky2's witness writer.
///
/// `set_proof_with_pis_target` assigns the proof's internals through
/// length-sensitive iterator paths: `zip_eq` (panics on mismatch, e.g. for the
/// FRI query-round list), debug-only length asserts (silent partial assignment
/// in release), and plain `zip` (silently leaves trailing targets unset, e.g.
/// for Merkle caps). A proof with the expected public-input length but
/// internally inconsistent vectors would otherwise crash the process or defer
/// the failure to prove time. Plonky2's own shape validation is private to the
/// crate and only runs inside `verify`, after witness filling.
///
/// `label` names the proof kind in error messages (e.g. "leaf proof").
pub fn ensure_proof_shape_matches_targets(
    proof_t: &ProofWithPublicInputsTarget<D>,
    proof: &ProofWithPublicInputs<F, C, D>,
    slot: usize,
    label: &str,
) -> Result<()> {
    // With fewer public inputs than targets, set_proof_with_pis_target's
    // internal zip_eq would panic instead of erroring.
    ensure_len_matches(
        proof.public_inputs.len(),
        proof_t.public_inputs.len(),
        label,
        slot,
        "public inputs",
    )?;

    let p = &proof.proof;
    let t = &proof_t.proof;

    ensure_len_matches(
        p.wires_cap.0.len(),
        t.wires_cap.0.len(),
        label,
        slot,
        "wires_cap",
    )?;
    ensure_len_matches(
        p.plonk_zs_partial_products_cap.0.len(),
        t.plonk_zs_partial_products_cap.0.len(),
        label,
        slot,
        "plonk_zs_partial_products_cap",
    )?;
    ensure_len_matches(
        p.quotient_polys_cap.0.len(),
        t.quotient_polys_cap.0.len(),
        label,
        slot,
        "quotient_polys_cap",
    )?;

    let o = &p.openings;
    let ot = &t.openings;
    ensure_len_matches(
        o.constants.len(),
        ot.constants.len(),
        label,
        slot,
        "openings.constants",
    )?;
    ensure_len_matches(
        o.plonk_sigmas.len(),
        ot.plonk_sigmas.len(),
        label,
        slot,
        "openings.plonk_sigmas",
    )?;
    ensure_len_matches(o.wires.len(), ot.wires.len(), label, slot, "openings.wires")?;
    ensure_len_matches(
        o.plonk_zs.len(),
        ot.plonk_zs.len(),
        label,
        slot,
        "openings.plonk_zs",
    )?;
    ensure_len_matches(
        o.plonk_zs_next.len(),
        ot.plonk_zs_next.len(),
        label,
        slot,
        "openings.plonk_zs_next",
    )?;
    ensure_len_matches(
        o.partial_products.len(),
        ot.partial_products.len(),
        label,
        slot,
        "openings.partial_products",
    )?;
    ensure_len_matches(
        o.quotient_polys.len(),
        ot.quotient_polys.len(),
        label,
        slot,
        "openings.quotient_polys",
    )?;
    ensure_len_matches(
        o.lookup_zs.len(),
        ot.lookup_zs.len(),
        label,
        slot,
        "openings.lookup_zs",
    )?;
    ensure_len_matches(
        o.lookup_zs_next.len(),
        ot.next_lookup_zs.len(),
        label,
        slot,
        "openings.lookup_zs_next",
    )?;

    let f = &p.opening_proof;
    let ft = &t.opening_proof;

    ensure_len_matches(
        f.commit_phase_merkle_caps.len(),
        ft.commit_phase_merkle_caps.len(),
        label,
        slot,
        "opening_proof.commit_phase_merkle_caps",
    )?;
    for (i, (cap, cap_t)) in f
        .commit_phase_merkle_caps
        .iter()
        .zip(ft.commit_phase_merkle_caps.iter())
        .enumerate()
    {
        ensure_len_matches(
            cap.0.len(),
            cap_t.0.len(),
            label,
            slot,
            &format!("opening_proof.commit_phase_merkle_caps[{i}]"),
        )?;
    }

    ensure_len_matches(
        f.query_round_proofs.len(),
        ft.query_round_proofs.len(),
        label,
        slot,
        "opening_proof.query_round_proofs",
    )?;
    for (i, (round, round_t)) in f
        .query_round_proofs
        .iter()
        .zip(ft.query_round_proofs.iter())
        .enumerate()
    {
        ensure_len_matches(
            round.initial_trees_proof.evals_proofs.len(),
            round_t.initial_trees_proof.evals_proofs.len(),
            label,
            slot,
            &format!("opening_proof.query_round_proofs[{i}].initial_trees_proof.evals_proofs"),
        )?;
        for (j, ((evals, merkle), (evals_t, merkle_t))) in round
            .initial_trees_proof
            .evals_proofs
            .iter()
            .zip(round_t.initial_trees_proof.evals_proofs.iter())
            .enumerate()
        {
            ensure_len_matches(
                evals.len(),
                evals_t.len(),
                label,
                slot,
                &format!(
                    "opening_proof.query_round_proofs[{i}].initial_trees_proof.evals_proofs[{j}].evals"
                ),
            )?;
            ensure_len_matches(
                merkle.siblings.len(),
                merkle_t.siblings.len(),
                label,
                slot,
                &format!(
                    "opening_proof.query_round_proofs[{i}].initial_trees_proof.evals_proofs[{j}].siblings"
                ),
            )?;
        }

        ensure_len_matches(
            round.steps.len(),
            round_t.steps.len(),
            label,
            slot,
            &format!("opening_proof.query_round_proofs[{i}].steps"),
        )?;
        for (j, (step, step_t)) in round.steps.iter().zip(round_t.steps.iter()).enumerate() {
            ensure_len_matches(
                step.evals.len(),
                step_t.evals.len(),
                label,
                slot,
                &format!("opening_proof.query_round_proofs[{i}].steps[{j}].evals"),
            )?;
            ensure_len_matches(
                step.merkle_proof.siblings.len(),
                step_t.merkle_proof.siblings.len(),
                label,
                slot,
                &format!("opening_proof.query_round_proofs[{i}].steps[{j}].merkle_proof.siblings"),
            )?;
        }
    }

    ensure_len_matches(
        f.final_poly.coeffs.len(),
        ft.final_poly.0.len(),
        label,
        slot,
        "opening_proof.final_poly",
    )?;

    Ok(())
}

pub fn ensure_proof_public_input_len(
    proof: &ProofWithPublicInputs<F, C, D>,
    expected_len: usize,
    label: &str,
) -> Result<()> {
    let actual_len = proof.public_inputs.len();
    if actual_len != expected_len {
        return Err(anyhow!(
            "{} public input length mismatch: expected {}, got {}",
            label,
            expected_len,
            actual_len
        ));
    }

    Ok(())
}

pub fn leaf_proof_asset_id(proof: &ProofWithPublicInputs<F, C, D>) -> Result<u32> {
    ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
    proof.public_inputs[ASSET_ID_START]
        .to_canonical_u64()
        .try_into()
        .map_err(|_| anyhow!("leaf proof asset_id exceeds u32 range"))
}

pub fn private_batch_num_leaves_from_padded_pi_len(pi_len: usize) -> Result<usize> {
    if pi_len < aggregated_output::HEADER_LEN {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is smaller than the fixed header {}",
            pi_len,
            aggregated_output::HEADER_LEN
        ));
    }

    let payload_len = pi_len - aggregated_output::HEADER_LEN;
    if !payload_len.is_multiple_of(LEAF_PI_LEN) {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is malformed: expected {} + N*{}",
            pi_len,
            aggregated_output::HEADER_LEN,
            LEAF_PI_LEN
        ));
    }

    let num_leaves = payload_len / LEAF_PI_LEN;
    validate_proof_count(num_leaves, "private-batch num_leaves")?;

    Ok(num_leaves)
}

#[cfg(test)]
mod tests {
    use super::private_batch_num_leaves_from_padded_pi_len;
    use super::{
        commit_artifact_set, ensure_artifact_basename, read_artifact_file,
        sweep_stale_artifact_droppings, MAX_ARTIFACT_FILE_BYTES,
    };

    #[test]
    fn private_batch_num_leaves_from_padded_pi_len_rejects_malformed_lengths() {
        let err = private_batch_num_leaves_from_padded_pi_len(9).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    /// Pinning must compare raw artifact bytes to a canonical rebuild and never
    /// feed untrusted common data into `CommonCircuitData::from_bytes`. That
    /// deserializer reserves vector capacities from length fields in the
    /// artifact; a small buffer of enormous little-endian usizes would
    /// previously force large `try_reserve` calls (or allocator failure)
    /// before the canonical check could reject it (audit finding).
    #[test]
    fn load_canonical_private_batch_rejects_poisoned_common_by_byte_pin() {
        use super::{
            canonical_leaf_verifier_data, load_canonical_private_batch_verifier_data,
        };

        let mut poisoned = vec![0u8; 4096];
        for i in (0..poisoned.len()).step_by(8) {
            poisoned[i..i + 8].copy_from_slice(&(usize::MAX / 16).to_le_bytes());
        }
        let leaf = canonical_leaf_verifier_data();
        let err = load_canonical_private_batch_verifier_data(
            &poisoned,
            &poisoned[..128],
            &leaf,
            1,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match the canonical"),
            "poisoned common must fail the byte pin, got: {err}"
        );
    }

    #[test]
    fn ensure_artifact_basename_accepts_plain_filenames() {
        for name in ["common.bin", "config.json", "dummy_private_batch_proof.bin", "a"] {
            ensure_artifact_basename(name).unwrap_or_else(|e| {
                panic!("expected {name:?} to be accepted, got: {e}");
            });
        }
    }

    /// Audit finding: unvalidated artifact names let `bins_dir.join(name)`
    /// (and the `.{name}.tmp-…` staging form) escape the artifact directory.
    /// Only a single normal path component is allowed.
    #[test]
    fn ensure_artifact_basename_rejects_directory_components() {
        for name in [
            "",
            ".",
            "..",
            "../common.bin",
            "foo/bar",
            "foo/../bar",
            "/etc/passwd",
            "./common.bin",
            "common.bin/",
            "a\0b",
        ] {
            let err = ensure_artifact_basename(name).expect_err(&format!(
                "expected {name:?} to be rejected"
            ));
            let msg = err.to_string();
            assert!(
                msg.contains("basename")
                    || msg.contains("directory components")
                    || msg.contains("NUL"),
                "unexpected error for {name:?}: {msg}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn ensure_artifact_basename_rejects_windows_separators() {
        let err = ensure_artifact_basename("foo\\bar").unwrap_err();
        assert!(
            err.to_string().contains("directory components"),
            "got: {err}"
        );
    }

    /// A hostile name in either `files` or `remove_stale` must fail before any
    /// path under / beside `bins_dir` is touched.
    #[test]
    fn commit_artifact_set_rejects_non_basename_names_before_touching_disk() {
        let dir = std::env::temp_dir().join(format!(
            "qp-artifact-basename-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Outside-target marker: must remain untouched if validation works.
        let outside = std::env::temp_dir().join(format!(
            "qp-artifact-basename-victim-{}",
            std::process::id()
        ));
        std::fs::write(&outside, b"untouched").unwrap();

        let err = commit_artifact_set(
            &dir,
            &[("../qp-artifact-basename-victim-should-not-exist", b"x".to_vec())],
            &[],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("directory components")
                || err.to_string().contains("basename"),
            "got: {err}"
        );

        let err = commit_artifact_set(&dir, &[("ok.bin", b"x".to_vec())], &["../outside"])
            .unwrap_err();
        assert!(
            err.to_string().contains("directory components")
                || err.to_string().contains("basename"),
            "got: {err}"
        );

        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        // Nothing staged or published inside bins_dir either.
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());

        let _ = std::fs::remove_file(&outside);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The sweep must remove exactly the `.<name>.tmp-<pid>-<rand>` /
    /// `.<name>.old-<pid>-<rand>` patterns `commit_artifact_set` generates —
    /// including directory-shaped moved-aside entries — and leave everything
    /// else (live artifacts, unrelated dotfiles, near-miss names) alone.
    #[test]
    fn sweep_removes_publish_droppings_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("qp-sweep-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Droppings: staged file, moved-aside file, directory-shaped
        // moved-aside entry (a planted directory a publish moved aside).
        std::fs::write(dir.join(".common.bin.tmp-42-00112233445566ff"), b"x").unwrap();
        std::fs::write(dir.join(".verifier.bin.old-42-00112233445566ff"), b"x").unwrap();
        std::fs::create_dir(dir.join(".config.json.old-42-aabbccddeeff0011")).unwrap();

        // Survivors: live artifact, unrelated dotfiles, near-miss suffixes.
        std::fs::write(dir.join("common.bin"), b"live").unwrap();
        std::fs::write(dir.join(".gitignore"), b"*.log").unwrap();
        std::fs::write(dir.join(".config.json.old-backup"), b"manual backup").unwrap();
        std::fs::write(dir.join(".x.tmp-notapid-00112233445566ff"), b"x").unwrap();
        std::fs::write(dir.join(".x.tmp-42-shorthex"), b"x").unwrap();
        std::fs::write(dir.join("common.bin.tmp-42-00112233445566ff"), b"no dot").unwrap();

        let removed = sweep_stale_artifact_droppings(&dir).unwrap();
        assert_eq!(removed, 3, "exactly the three droppings must be removed");

        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ".config.json.old-backup".to_string(),
                ".gitignore".to_string(),
                ".x.tmp-42-shorthex".to_string(),
                ".x.tmp-notapid-00112233445566ff".to_string(),
                "common.bin".to_string(),
                "common.bin.tmp-42-00112233445566ff".to_string(),
            ]
        );

        // A missing directory is a no-op, not an error (fresh builder runs).
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(sweep_stale_artifact_droppings(&dir).unwrap(), 0);
    }

    /// An unremovable dropping must not fail the sweep, and must not be
    /// counted as removed (it is reported on stderr, not silently skipped —
    /// the warning itself is not capturable in-process, so this asserts the
    /// count and survival).
    #[test]
    #[cfg(unix)]
    fn sweep_survives_unremovable_dropping_without_counting_it() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("qp-sweep-stuck-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A directory-shaped dropping whose contents cannot be unlinked:
        // remove_file fails (it is a directory) and remove_dir_all fails
        // (no write permission on the directory itself).
        let stuck = dir.join(".common.bin.old-42-00112233445566ff");
        std::fs::create_dir(&stuck).unwrap();
        std::fs::write(stuck.join("inner"), b"x").unwrap();
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o555)).unwrap();

        let removed = sweep_stale_artifact_droppings(&dir).unwrap();
        assert_eq!(removed, 0, "a still-present entry must not be counted");
        assert!(stuck.exists());

        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_artifact_file_round_trips_normal_files_and_rejects_oversized_ones() {
        let dir =
            std::env::temp_dir().join(format!("qp-artifact-read-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let normal = dir.join("normal.bin");
        std::fs::write(&normal, b"artifact bytes").unwrap();
        assert_eq!(read_artifact_file(&normal).unwrap(), b"artifact bytes");

        // A sparse file costs no disk but still claims an oversized length,
        // exactly like an attacker-planted artifact would.
        let oversized = dir.join("oversized.bin");
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_ARTIFACT_FILE_BYTES + 1)
            .unwrap();
        let err = read_artifact_file(&oversized).unwrap_err();
        assert!(err.to_string().contains("exceeds the"), "got: {err}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A FIFO planted at an expected `*.bin` path must produce a prompt
    /// invalid-artifact error, not a hang: a blocking `File::open` on a FIFO
    /// with no writer stalls forever, before the size check can run,
    /// converting artifact loading into a startup denial of service when the
    /// artifact directory is untrusted (audit finding: non-regular files
    /// bypass the bounded-read protections).
    #[cfg(unix)]
    #[test]
    fn read_artifact_file_rejects_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir =
            std::env::temp_dir().join(format!("qp-artifact-fifo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let fifo = dir.join("leaf_common.bin");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) },
            0,
            "mkfifo failed"
        );

        // Run the read on a helper thread so a regression (blocking open or
        // read) surfaces as a test failure instead of hanging the suite.
        let (tx, rx) = std::sync::mpsc::channel();
        let fifo_for_thread = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_artifact_file(&fifo_for_thread).map(drop));
        });

        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(result) => {
                let err = result.unwrap_err();
                assert!(err.to_string().contains("not a regular file"), "got: {err}");
            }
            Err(_) => panic!("read_artifact_file blocked on a FIFO artifact path"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
