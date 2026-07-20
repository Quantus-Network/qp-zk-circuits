//! Prebuild / serialization helpers for the monolithic Private-batch aggregation circuit.
//!
//! Generates: `private_batch_common.bin`, `private_batch_verifier.bin`, `private_batch_prover.bin`
//!
//! Expects `common.bin` and `verifier.bin` to already exist in the output directory.

use anyhow::{anyhow, Context, Result};
use plonky2::{
    plonk::circuit_data::CommonCircuitData,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use qp_wormhole_inputs::validate_proof_count;
use std::{
    fs::{create_dir_all, write},
    path::Path,
};
use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};

use crate::common::utils::load_canonical_leaf_verifier_data;
use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;

/// Generate prebuilt Private-batch aggregation circuit binaries.
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
    let leaf_common_bytes = std::fs::read(output_path.join("common.bin"))
        .with_context(|| format!("Failed to read {}/common.bin", output_path.display()))?;
    let leaf_verifier_bytes = std::fs::read(output_path.join("verifier.bin"))
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
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    // Generate the dummy private-batch proof template (an all-dummy batch) used to pad
    // partial public batches. Must happen BEFORE consuming circuit_data below
    // (prove() borrows, prover_data() moves). Only possible/needed when proving
    // artifacts are requested (requires the leaf dummy proof from the same run).
    if include_prover {
        let dummy_batch_proof_bytes = generate_dummy_private_batch_proof(
            &circuit_data,
            &agg_targets,
            &leaf.common,
            output_path,
            num_leaf_proofs,
        )?;
        write(
            output_path.join("dummy_private_batch_proof.bin"),
            &dummy_batch_proof_bytes,
        )?;
        println!(
            "Saved {}/dummy_private_batch_proof.bin ({} bytes)",
            output_path.display(),
            dummy_batch_proof_bytes.len()
        );
    }

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    let agg_common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("Failed to serialize aggregated common data: {}", e))?;
    write(
        output_path.join("private_batch_common.bin"),
        agg_common_bytes,
    )?;
    println!("Saved {}/private_batch_common.bin", output_path.display());

    let agg_verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;
    write(
        output_path.join("private_batch_verifier.bin"),
        agg_verifier_only_bytes,
    )?;
    println!("Saved {}/private_batch_verifier.bin", output_path.display());

    if include_prover {
        let agg_prover_only_bytes = prover_data
            .prover_only
            .to_bytes(&generator_serializer, common_data)
            .map_err(|e| anyhow!("Failed to serialize aggregated prover data: {}", e))?;
        write(
            output_path.join("private_batch_prover.bin"),
            agg_prover_only_bytes,
        )?;
        println!("Saved {}/private_batch_prover.bin", output_path.display());
    } else {
        println!("Skipping aggregated prover binary generation");
    }
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

    let dummy_leaf_bytes = std::fs::read(bins_dir.join("dummy_proof.bin"))
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
