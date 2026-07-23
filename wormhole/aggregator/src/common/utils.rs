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
/// The size is checked via `fstat` on the already-opened handle (no
/// stat-then-open race), and the read itself is additionally capped with
/// `Read::take` in case the file grows after the check.
#[cfg(feature = "std")]
pub fn read_artifact_file(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open artifact file {}", path.display()))?;
    let claimed_len = file
        .metadata()
        .with_context(|| format!("failed to stat artifact file {}", path.display()))?
        .len();
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

/// Load verifier circuit data (common + verifier-only) from serialized bytes.
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

/// Load leaf verifier data and reject anything that is not the canonical Wormhole leaf circuit.
pub fn load_canonical_leaf_verifier_data(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
) -> Result<VerifierCircuitData<F, C, D>> {
    let loaded = load_verifier_data_from_bytes(common_bytes, verifier_only_bytes, "leaf")?;
    ensure_verifier_data_matches_canonical(&loaded, &canonical_leaf_verifier_data(), "leaf")?;
    Ok(loaded)
}

/// Load private-batch verifier data pinned to the canonical private-batch circuit for
/// `num_leaf_proofs`. `leaf` must be canonical leaf verifier data (loaded pinned or rebuilt).
pub fn load_canonical_private_batch_verifier_data(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaf_proofs: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    let loaded = load_verifier_data_from_bytes(common_bytes, verifier_only_bytes, "private_batch")?;
    let canonical = canonical_private_batch_verifier_data(leaf, num_leaf_proofs)?;
    ensure_verifier_data_matches_canonical(&loaded, &canonical, "private_batch")?;
    Ok(loaded)
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
    use super::{read_artifact_file, MAX_ARTIFACT_FILE_BYTES};

    #[test]
    fn private_batch_num_leaves_from_padded_pi_len_rejects_malformed_lengths() {
        let err = private_batch_num_leaves_from_padded_pi_len(9).unwrap_err();
        assert!(err.to_string().contains("malformed"));
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
}
