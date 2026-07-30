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
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_inputs::validate_proof_count;
use std::{fs::create_dir_all, path::Path};
use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};

use crate::common::utils::{
    commit_artifact_set, load_canonical_leaf_verifier_data, read_artifact_file,
};
use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;

/// Generate prebuilt Private-batch aggregation circuit binaries.
///
/// Writes private-batch verifier artifacts (and optionally the dummy
/// private-batch padding template). Prefer
/// `generate_all_circuit_binaries` for production regenerates so a failed
/// stage never mixes generations in the live output directory
/// (`wormhole/THREAT_MODEL.md`). When `include_prover` is `false`, any
/// pre-existing `dummy_private_batch_proof.bin` is removed.
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
        "Building prebuilt private-batch aggregation circuit (num_leaf_proofs={}, ZK row blinding)...",
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

    // Load AND validate the leaf dummy template before the expensive
    // aggregation-circuit build. Every other consumer of dummy_proof.bin
    // (the private/public batch prover constructors) enforces the dummy
    // sentinel via verify_dummy_leaf_template; the build path must too,
    // or a valid-but-non-dummy leaf planted at dummy_proof.bin gets baked
    // into the published dummy_private_batch_proof.bin as a "dummy"
    // template that actually settles a real payout (audit finding).
    let dummy_leaf = if include_prover {
        Some(load_validated_dummy_leaf_template(output_path, &leaf)?)
    } else {
        None
    };

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
    let dummy_batch_proof_bytes = match dummy_leaf {
        Some(dummy_leaf) => Some(generate_dummy_private_batch_proof(
            &circuit_data,
            &agg_targets,
            dummy_leaf,
            num_leaf_proofs,
        )?),
        None => None,
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

    // Without prover output, drop a stale dummy template from an earlier run
    // (it would fail template verification against the fresh verifier data).
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

/// Load `dummy_proof.bin` and verify it is a genuine all-dummy leaf template
/// (dummy sentinel: zero block hash, zero outputs, zero asset_id, zero exit
/// accounts, AND a passing cryptographic verify against the pinned leaf
/// verifier) before it gets replayed into every slot of the published
/// `dummy_private_batch_proof.bin`. This mirrors the check the prover
/// constructors apply to the very same artifact; without it, a re-run over a
/// pre-existing or attacker-populated bins dir would label a REAL proof as
/// the all-dummy padding template and report success (#97026 family).
fn load_validated_dummy_leaf_template(
    bins_dir: &Path,
    leaf: &plonky2::plonk::circuit_data::VerifierCircuitData<F, C, D>,
) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>> {
    let dummy_leaf_bytes = read_artifact_file(&bins_dir.join("dummy_proof.bin"))
        .with_context(|| format!("Failed to read {}/dummy_proof.bin", bins_dir.display()))?;
    let dummy_leaf = crate::dummy_proof::load_dummy_proof(dummy_leaf_bytes, &leaf.common)
        .map_err(|e| anyhow!("Failed to deserialize dummy leaf proof: {}", e))?;
    crate::private_batch::prover::verify_dummy_leaf_template(&dummy_leaf, leaf).with_context(
        || {
            format!(
                "{}/dummy_proof.bin is not a genuine all-dummy leaf template; refusing to bake \
                 it into dummy_private_batch_proof.bin",
                bins_dir.display()
            )
        },
    )?;
    Ok(dummy_leaf)
}

/// Prove a private batch consisting entirely of dummy leaf proofs.
///
/// The resulting proof has `block_hash == 0` (the public-batch dummy sentinel),
/// zeroed exit slots, and dummy-replaced nullifiers, and is used by the
/// public-batch prover to pad partial batches. `dummy_leaf` must come from
/// [`load_validated_dummy_leaf_template`].
fn generate_dummy_private_batch_proof(
    circuit_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    targets: &crate::private_batch::circuit::circuit_logic::PrivateBatchCircuitTargets,
    dummy_leaf: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>,
    num_leaf_proofs: usize,
) -> Result<Vec<u8>> {
    use plonky2::iop::witness::PartialWitness;
    use zk_circuits_common::utils::bytes_to_digest;

    println!("Generating dummy private-batch proof for public-batch padding...");

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
        std::fs::write(
            dir.join("verifier.bin"),
            leaf.verifier_only.to_bytes().unwrap(),
        )
        .unwrap();
    }

    /// A valid-but-non-dummy leaf proof planted at `dummy_proof.bin` must not
    /// be baked into the published `dummy_private_batch_proof.bin`. The
    /// recursive circuit only forces the leaf to be cryptographically valid;
    /// a REAL leaf (nonzero block_hash) replayed into every slot passes all
    /// cross-slot consistency checks, so without the sentinel check the build
    /// would emit a real private-batch proof labelled as the all-dummy
    /// padding template and report success (audit finding).
    #[test]
    fn build_rejects_non_dummy_leaf_planted_at_dummy_proof_bin() {
        use test_helpers::TestInputs as _;
        use wormhole_circuit::block_header::header::HeaderInputs;
        use wormhole_circuit::inputs::CircuitInputs;

        let dir = temp_dir("poisoned-dummy");
        write_canonical_leaf_artifacts(&dir);

        // A REAL leaf proof against the canonical leaf circuit: genuine block
        // hash, so it deserializes and verifies fine but violates the dummy
        // sentinel (non-zero block_hash).
        let mut inputs = CircuitInputs::test_inputs_0();
        inputs.public.block_hash = HeaderInputs::try_from(&inputs)
            .expect("header inputs")
            .block_hash();
        let real_leaf = wormhole_prover::build_fresh()
            .commit(&inputs)
            .unwrap()
            .prove()
            .unwrap();
        std::fs::write(dir.join("dummy_proof.bin"), real_leaf.to_bytes()).unwrap();

        let err = generate_private_batch_circuit_binaries(&dir, 1, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a genuine all-dummy leaf template"),
            "poisoned dummy_proof.bin must be rejected with attribution, got: {msg}"
        );
        assert!(
            msg.contains("non-zero block_hash"),
            "the sentinel violation must be named, got: {msg}"
        );
        assert!(
            !dir.join("dummy_private_batch_proof.bin").exists()
                && !dir.join("private_batch_common.bin").exists(),
            "a rejected template must not publish any private-batch artifacts"
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
