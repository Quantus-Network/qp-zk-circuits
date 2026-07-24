//! Prebuild / serialization helpers for the monolithic Private-batch aggregation circuit.
//!
//! Generates: `private_batch_common.bin`, `private_batch_verifier.bin`
//!
//! No `private_batch_prover.bin` is emitted: `PrivateBatchProver` always rebuilds
//! the aggregation prover from source, because a poisoned prover artifact could
//! exfiltrate witness data through the proof's public-input list. `include_prover`
//! now only controls generation of the dummy private-batch proof used to pad
//! partial public batches.
//!
//! Expects `common.bin` and `verifier.bin` to already exist in the output directory.

use anyhow::{anyhow, Context, Result};
use plonky2::{plonk::circuit_data::CommonCircuitData, util::serialization::DefaultGateSerializer};
use qp_wormhole_inputs::validate_proof_count;
use std::{fs::create_dir_all, path::Path};
use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};

use crate::common::utils::{
    commit_artifact_set, load_canonical_leaf_verifier_data, read_artifact_file,
};
use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;

/// Generate prebuilt Private-batch aggregation circuit binaries.
///
/// The private-batch files are published all-or-nothing (see
/// `commit_artifact_set` in `common::utils`), so a failed re-run over an
/// existing bins dir never leaves a fresh `private_batch_common.bin` beside a
/// stale `private_batch_verifier.bin` or `dummy_private_batch_proof.bin`.
/// When `include_prover` is `false`, any pre-existing
/// `dummy_private_batch_proof.bin` is removed as part of the same publish: a
/// stale template would fail verification against the fresh verifier data and
/// take the whole bins directory offline for public-batch proving.
/// Whole-directory consistency across all stages (leaf, private-batch,
/// public-batch, `config.json`) is still only guaranteed by the staging
/// `generate_all_circuit_binaries` flow in `circuit-builder`; prefer it unless
/// deliberately regenerating this one stage into an existing set.
pub fn generate_private_batch_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    // Bound the per-layer count before any circuit construction (#97021, #97070).
    validate_proof_count(num_leaf_proofs, "num_leaf_proofs")?;
    create_dir_all(output_path)?;

    println!(
        "Building prebuilt private-batch aggregation circuit (num_leaf_proofs={})...",
        num_leaf_proofs
    );

    // Pin the leaf artifacts to the canonical Wormhole leaf circuit BEFORE baking
    // their verifier key into the recursive circuit as constants. Without this, a
    // substituted or stale common.bin/verifier.bin would silently produce
    // private-batch artifacts with the wrong embedded inner verifier key.
    let leaf_common_bytes = read_artifact_file(&output_path.join("common.bin"))
        .with_context(|| format!("Failed to read {}/common.bin", output_path.display()))?;
    let leaf_verifier_bytes = read_artifact_file(&output_path.join("verifier.bin"))
        .with_context(|| format!("Failed to read {}/verifier.bin", output_path.display()))?;
    let leaf = load_canonical_leaf_verifier_data(&leaf_common_bytes, &leaf_verifier_bytes)?;

    let agg_circuit = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf.common,
        &leaf.verifier_only,
        num_leaf_proofs,
    )?;

    let agg_targets = agg_circuit.targets();
    let circuit_data = agg_circuit.build_circuit();

    let gate_serializer = DefaultGateSerializer;

    // Generate the dummy private-batch proof template (an all-dummy batch) used to pad
    // partial public batches. Must happen BEFORE consuming circuit_data below
    // (prove() borrows, prover_data() moves). Only possible/needed when proving
    // artifacts are requested (requires the leaf dummy proof from the same run).
    let dummy_batch_proof_bytes = if include_prover {
        Some(generate_dummy_private_batch_proof(
            &circuit_data,
            &agg_targets,
            &leaf.common,
            output_path,
            num_leaf_proofs,
        )?)
    } else {
        None
    };

    let verifier_data = circuit_data.verifier_data();
    let common_data = &verifier_data.common;

    let agg_common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize aggregated common data: {}", e))?;
    let agg_verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;

    // Publish the whole set all-or-nothing. Without prover output, a stale
    // dummy template from an earlier run is removed as part of the same swap:
    // it would fail template verification against the fresh verifier data.
    let mut files: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut remove_stale: Vec<&str> = Vec::new();
    match dummy_batch_proof_bytes {
        Some(bytes) => {
            println!(
                "Publishing {}/dummy_private_batch_proof.bin ({} bytes)",
                output_path.display(),
                bytes.len()
            );
            files.push(("dummy_private_batch_proof.bin", bytes));
        }
        None => remove_stale.push("dummy_private_batch_proof.bin"),
    }
    files.push(("private_batch_common.bin", agg_common_bytes));
    files.push(("private_batch_verifier.bin", agg_verifier_only_bytes));
    commit_artifact_set(output_path, &files, &remove_stale)?;
    println!("Saved {}/private_batch_common.bin", output_path.display());
    println!("Saved {}/private_batch_verifier.bin", output_path.display());

    Ok(())
}

/// Prove a private batch consisting entirely of dummy leaf proofs.
///
/// The resulting proof has `block_hash == 0` (the public-batch dummy sentinel),
/// zeroed exit slots, and dummy-replaced nullifiers, and is used by the
/// public-batch prover to pad partial batches. Requires `dummy_proof.bin`
/// (the leaf dummy proof) from the same generation run.
fn generate_dummy_private_batch_proof(
    circuit_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    targets: &crate::private_batch::circuit::circuit_logic::PrivateBatchCircuitTargets,
    leaf_common: &CommonCircuitData<F, D>,
    bins_dir: &Path,
    num_leaf_proofs: usize,
) -> Result<Vec<u8>> {
    use plonky2::iop::witness::PartialWitness;
    use zk_circuits_common::utils::bytes_to_digest;

    println!("Generating dummy private-batch proof for public-batch padding...");

    let dummy_leaf_bytes = read_artifact_file(&bins_dir.join("dummy_proof.bin"))
        .with_context(|| format!("Failed to read {}/dummy_proof.bin", bins_dir.display()))?;
    let dummy_leaf = crate::dummy_proof::load_dummy_proof(dummy_leaf_bytes, leaf_common)
        .map_err(|e| anyhow!("Failed to deserialize dummy leaf proof: {}", e))?;

    let proofs = vec![dummy_leaf; num_leaf_proofs];
    let dummy_nullifier_pre_images: Vec<[F; 4]> = (0..num_leaf_proofs)
        .map(|_| bytes_to_digest(crate::dummy_proof::generate_random_nullifier_preimage()))
        .collect();

    let mut pw = PartialWitness::new();
    crate::private_batch::prover::fill_private_batch_witness(
        &mut pw,
        targets,
        &proofs,
        &dummy_nullifier_pre_images,
    )?;

    let proof = circuit_data
        .prove(pw)
        .map_err(|e| anyhow!("Failed to prove dummy private batch: {}", e))?;
    Ok(proof.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::MAX_ARTIFACT_FILE_BYTES;
    use std::fs::File;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qp-private-batch-build-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_all(&dir).unwrap();
        dir
    }

    /// Write canonical leaf artifacts into `dir` so the private-batch
    /// generation's canonical pinning succeeds.
    fn write_canonical_leaf_artifacts(dir: &Path) {
        let leaf = crate::common::utils::canonical_leaf_verifier_data();
        let gate_serializer = DefaultGateSerializer;
        std::fs::write(
            dir.join("common.bin"),
            leaf.common.to_bytes(&gate_serializer).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("verifier.bin"), leaf.verifier_only.to_bytes().unwrap()).unwrap();
    }

    /// The private-batch files are consumed as a matched set (public-batch
    /// constructors pin them against a canonical rebuild and verify the dummy
    /// template against them), so a directory holding a fresh file from one
    /// generation beside a stale file from another is rejected until
    /// regenerated. A publish that fails partway must therefore either leave
    /// the previous set fully intact or replace it wholesale — never mix
    /// (audit finding: non-atomic artifact-set publication).
    #[test]
    fn failed_artifact_publish_never_leaves_mixed_private_batch_set() {
        let dir = temp_dir("mixed-set");
        write_canonical_leaf_artifacts(&dir);
        std::fs::write(dir.join("private_batch_common.bin"), b"old common").unwrap();
        // A directory squatting on the verifier path makes a naive in-place
        // write of the second file fail after the first was already clobbered.
        create_dir_all(dir.join("private_batch_verifier.bin")).unwrap();

        let result = generate_private_batch_circuit_binaries(&dir, 1, false);

        let common_now = std::fs::read(dir.join("private_batch_common.bin")).unwrap();
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
                    dir.join("private_batch_verifier.bin").is_file(),
                    "a successful publish must leave a real verifier artifact"
                );
            }
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A verifier-only rerun (`include_prover == false`) over a directory that
    /// previously held prover output must not leave the old
    /// `dummy_private_batch_proof.bin` beside freshly regenerated
    /// common/verifier data: the public-batch prover verifies the template
    /// against the pinned private-batch verifier at startup, so a stale
    /// template takes the whole bins directory offline (audit finding:
    /// non-atomic artifact-set publication).
    #[test]
    fn verifier_only_rerun_removes_stale_dummy_template() {
        let dir = temp_dir("stale-dummy");
        write_canonical_leaf_artifacts(&dir);
        std::fs::write(dir.join("dummy_private_batch_proof.bin"), b"stale template").unwrap();

        generate_private_batch_circuit_binaries(&dir, 1, false).unwrap();

        assert!(
            !dir.join("dummy_private_batch_proof.bin").exists(),
            "a verifier-only rerun must remove the stale dummy template"
        );
        // No staging or moved-aside droppings either.
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "common.bin".to_string(),
                "private_batch_common.bin".to_string(),
                "private_batch_verifier.bin".to_string(),
                "verifier.bin".to_string(),
            ],
            "publish must not leave temp/old files behind"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An oversized (sparse) leaf artifact must be rejected by the size cap
    /// before its contents are allocated into memory, not fed whole into
    /// deserialization and canonical comparison.
    #[test]
    fn oversized_leaf_common_artifact_is_rejected_by_size_cap() {
        let dir = temp_dir("oversized-common");
        File::create(dir.join("common.bin"))
            .unwrap()
            .set_len(MAX_ARTIFACT_FILE_BYTES + 1)
            .unwrap();
        std::fs::write(dir.join("verifier.bin"), b"irrelevant").unwrap();

        let err = generate_private_batch_circuit_binaries(&dir, 1, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds the"),
            "oversized artifact must be rejected by the size cap, got: {err:#}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
