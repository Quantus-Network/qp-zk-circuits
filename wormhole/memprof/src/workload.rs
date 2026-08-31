//! Pipeline phases under measurement:
//!   1. build leaf circuit (extract prover data, common, verifier_only, targets, dummy proof)
//!   2. generate N leaf proofs sequentially (reusing the prover circuit data)
//!   3. build the private-batch aggregation circuit
//!   4. commit + prove the aggregation
//!
//! Uses deterministic circuit inputs so the workload is self-contained.

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, ProverCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_aggregator::dummy_proof::load_dummy_proof;
use wormhole_aggregator::private_batch::prover::{PrivateBatchBuildMetrics, PrivateBatchProver};
use wormhole_aggregator::{build_dummy_circuit_inputs, generate_dummy_proof};
use wormhole_circuit::block_header::header::HeaderInputs;
use wormhole_circuit::circuit::circuit_logic::{CircuitTargets, WormholeCircuit};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_circuit::nullifier::Nullifier;
use wormhole_prover::fill_witness;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::serialization::{bytes_to_digest, digest_to_bytes as serialize_digest};
use zk_circuits_common::utils::{digest_to_bytes, u64_to_felts};

use crate::report::PhaseReport;

pub struct LeafContext {
    pub common: CommonCircuitData<F, D>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
    /// Prover circuit data for generating real leaf proofs (reused across multiple proofs).
    pub prover_data: ProverCircuitData<F, C, D>,
    /// Circuit targets for witness filling (from the same build as prover_data).
    pub targets: CircuitTargets,
}

fn print_private_batch_metrics(num_leaf_proofs: usize, metrics: PrivateBatchBuildMetrics) {
    eprintln!(
        "[metrics] private_batch n={} leaf_degree_bits={} unpadded_gates={} \
         degree_bits={} padded_gates={}",
        num_leaf_proofs,
        metrics.leaf_degree_bits,
        metrics.unpadded_gates,
        metrics.degree_bits,
        metrics.padded_gates,
    );
}

fn build_profile_circuit_inputs() -> Result<CircuitInputs> {
    let mut inputs = build_dummy_circuit_inputs()?;
    let fee_denominator = 10_000u64 - u64::from(inputs.public.volume_fee_bps);
    inputs.public.output_amount_1 =
        (u64::from(inputs.public.input_amount) * fee_denominator / 10_000) as u32;
    inputs.public.nullifier = digest_to_bytes(
        Nullifier::from_preimage(
            inputs.private.secret.expose_digest(),
            inputs.private.transfer_count,
        )
        .hash,
    );

    let account: [u8; 32] = inputs.private.unspendable_account.as_ref().try_into()?;
    let mut preimage = bytes_to_digest(&account).to_vec();
    preimage.extend(u64_to_felts(inputs.private.transfer_count));
    preimage.push(F::from_canonical_u32(inputs.public.asset_id));
    preimage.push(F::from_canonical_u32(inputs.public.input_amount));
    inputs.private.zk_tree_root = serialize_digest(&Poseidon2Hash::hash_no_pad(&preimage).elements);
    inputs.public.block_hash = HeaderInputs::try_from(&inputs)?.block_hash();
    Ok(inputs)
}

pub fn build_leaf_context(
    leaf_cfg: CircuitConfig,
    report: &mut PhaseReport,
) -> Result<LeafContext> {
    report.phase_start("build_leaf_circuit")?;

    // Build circuit ONCE - extract all data from this single build
    let circuit = WormholeCircuit::new(leaf_cfg)?;
    let unpadded_gates = circuit.num_gates();
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();
    eprintln!(
        "[metrics] leaf unpadded_gates={} degree_bits={} padded_gates={}",
        unpadded_gates,
        circuit_data.common.degree_bits(),
        circuit_data.common.degree(),
    );

    // Generate dummy proof before splitting circuit_data
    let dummy_bytes = generate_dummy_proof(&circuit_data, &targets)?;

    // Extract verifier data
    let verifier_data = circuit_data.verifier_data();
    let common = verifier_data.common.clone();
    let verifier_only = verifier_data.verifier_only.clone();

    // Extract prover data from the SAME build (targets match this circuit_data)
    let prover_data = circuit_data.prover_data();

    // Load dummy proof
    let dummy_proof = load_dummy_proof(dummy_bytes, &common)?;

    report.phase_end()?;

    Ok(LeafContext {
        common,
        verifier_only,
        dummy_proof,
        prover_data,
        targets,
    })
}

pub fn generate_leaf_proof(
    ctx: &LeafContext,
    idx: usize,
    release_after: bool,
    report: &mut PhaseReport,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    report.phase_start(&format!("gen_leaf_proof[{}]", idx))?;

    let inputs = build_profile_circuit_inputs()?;

    // Fill witness using targets from the same build as prover_data
    let mut pw = PartialWitness::new();
    fill_witness(&mut pw, &inputs, &ctx.targets)?;

    let proof = ctx
        .prover_data
        .prove(pw)
        .map_err(|e| anyhow::anyhow!("Failed to prove: {}", e))?;

    report.phase_end()?;
    if release_after {
        report.release_memory("after_gen_leaf_proof")?;
    }
    Ok(proof)
}

pub fn aggregate_fresh(
    leaf: &LeafContext,
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    num_leaf_proofs: usize,
    agg_config: CircuitConfig,
    release_after: bool,
    report: &mut PhaseReport,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    report.phase_start("build_agg_circuit")?;
    let (prover, metrics) = PrivateBatchProver::new_with_metrics(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        num_leaf_proofs,
        leaf.dummy_proof.clone(),
    )?;
    print_private_batch_metrics(num_leaf_proofs, metrics);
    report.phase_end()?;

    report.phase_start("agg_commit")?;
    let prover = prover.commit(leaf_proofs)?;
    report.phase_end()?;

    report.phase_start("agg_prove")?;
    let proof = prover.prove()?;
    report.phase_end()?;

    if release_after {
        report.release_memory("after_agg")?;
    }
    Ok(proof)
}

pub fn build_agg_circuit_only(
    leaf: &LeafContext,
    num_leaf_proofs: usize,
    agg_config: CircuitConfig,
    report: &mut PhaseReport,
) -> Result<()> {
    report.phase_start("build_agg_circuit_only")?;
    let (_, metrics) = PrivateBatchProver::new_with_metrics(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        num_leaf_proofs,
        leaf.dummy_proof.clone(),
    )?;
    print_private_batch_metrics(num_leaf_proofs, metrics);
    report.phase_end()?;
    Ok(())
}
