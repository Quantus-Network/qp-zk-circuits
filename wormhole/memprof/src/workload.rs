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
use wormhole_aggregator::private_batch::prover::{
    PrivateBatchBuildMetrics, PrivateBatchInputs, PrivateBatchProver,
};
use wormhole_aggregator::PrivateBatchShape;
use wormhole_aggregator::{build_dummy_circuit_inputs, generate_dummy_proof};
use wormhole_circuit::block_header::header::HeaderInputs;
use wormhole_circuit::circuit::circuit_logic::{CircuitTargets, WormholeCircuit};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_circuit::nullifier::Nullifier;
use wormhole_prover::fill_witness;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::serialization::{bytes_to_digest, digest_to_bytes as serialize_digest};
use zk_circuits_common::utils::{digest_to_bytes, u64_to_felts};
use zk_circuits_common::zk_merkle::{hash_node, Hash256, ARITY, SIBLINGS_PER_LEVEL};

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

fn print_private_batch_metrics(shape: PrivateBatchShape, metrics: PrivateBatchBuildMetrics) {
    eprintln!(
        "[metrics] private_batch n={} m={} leaf_degree_bits={} unpadded_gates={} \
         degree_bits={} padded_gates={}",
        shape.num_leaf_proofs,
        shape.num_exit_slots,
        metrics.leaf_degree_bits,
        metrics.unpadded_gates,
        metrics.degree_bits,
        metrics.padded_gates,
    );
}

const PROFILE_INPUT_AMOUNT: u32 = 100;

fn zk_leaf_hash(account: &[u8; 32], transfer_count: u64, asset_id: u32, amount: u32) -> Hash256 {
    let mut preimage = bytes_to_digest(account).to_vec();
    preimage.extend(u64_to_felts(transfer_count));
    preimage.push(F::from_canonical_u32(asset_id));
    preimage.push(F::from_canonical_u32(amount));
    serialize_digest(&Poseidon2Hash::hash_no_pad(&preimage).elements)
}

/// Sorted siblings, positions and root of a 4-ary merkle path for `leaf_index` in a
/// tree whose leaves are `leaves` padded with zero hashes to `ARITY^depth`. The tree
/// has at least one level so that several leaves can share a root.
fn merkle_path(
    leaf_index: usize,
    leaves: &[Hash256],
) -> Result<(Vec<[Hash256; SIBLINGS_PER_LEVEL]>, Vec<u8>, Hash256)> {
    let mut width = ARITY;
    while width < leaves.len() {
        width *= ARITY;
    }
    let mut nodes = leaves.to_vec();
    nodes.resize(width, [0u8; 32]);

    let mut siblings = Vec::new();
    let mut positions = Vec::new();
    let mut idx = leaf_index;
    while nodes.len() > 1 {
        let current = nodes[idx];
        let mut group: [Hash256; ARITY] = nodes[idx / ARITY * ARITY..][..ARITY].try_into()?;
        group.sort();
        let position = group
            .iter()
            .position(|h| *h == current)
            .ok_or_else(|| anyhow::anyhow!("leaf hash missing from its own node"))?;
        let level_siblings: Vec<Hash256> = group
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != position)
            .map(|(_, h)| *h)
            .collect();
        siblings.push(
            level_siblings
                .try_into()
                .map_err(|_| anyhow::anyhow!("expected {SIBLINGS_PER_LEVEL} siblings"))?,
        );
        positions.push(position as u8);

        nodes = nodes
            .chunks(ARITY)
            .map(|children| {
                hash_node(children.try_into().expect("chunks of ARITY"))
                    .map_err(|e| anyhow::anyhow!(e))
            })
            .collect::<Result<Vec<_>>>()?;
        idx /= ARITY;
    }
    Ok((siblings, positions, nodes[0]))
}

/// Inputs for `count` real leaf proofs that can be aggregated together: every leaf
/// spends a distinct `transfer_count` of the shared secret (distinct nullifiers) and
/// all leaves sit in one zk tree, so they commit to the same block hash.
pub fn build_profile_circuit_inputs(count: usize) -> Result<Vec<CircuitInputs>> {
    let template = build_dummy_circuit_inputs()?;
    let account: [u8; 32] = template.private.unspendable_account.as_ref().try_into()?;
    let leaf_hashes: Vec<Hash256> = (0..count as u64)
        .map(|tc| zk_leaf_hash(&account, tc, template.public.asset_id, PROFILE_INPUT_AMOUNT))
        .collect();

    let mut all = Vec::with_capacity(count);
    for idx in 0..count {
        let (siblings, positions, root) = merkle_path(idx, &leaf_hashes)?;
        let mut inputs = build_dummy_circuit_inputs()?;
        inputs.public.input_amount = PROFILE_INPUT_AMOUNT;
        inputs.private.transfer_count = idx as u64;
        inputs.public.nullifier = digest_to_bytes(
            Nullifier::from_preimage(inputs.private.secret.expose_digest(), idx as u64).hash,
        );
        inputs.private.zk_tree_root = root;
        inputs.private.zk_merkle_siblings = siblings;
        inputs.private.zk_merkle_positions = positions;
        inputs.public.block_hash = HeaderInputs::try_from(&inputs)?.block_hash();
        all.push(inputs);
    }
    Ok(all)
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
    inputs: &CircuitInputs,
    release_after: bool,
    report: &mut PhaseReport,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    report.phase_start(&format!("gen_leaf_proof[{}]", idx))?;

    // Fill witness using targets from the same build as prover_data
    let mut pw = PartialWitness::new();
    fill_witness(&mut pw, inputs, &ctx.targets)?;

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
    shape: PrivateBatchShape,
    agg_config: CircuitConfig,
    release_after: bool,
    report: &mut PhaseReport,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    report.phase_start("build_agg_circuit")?;
    let (prover, metrics) = PrivateBatchProver::new_with_metrics(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        shape,
        leaf.dummy_proof.clone(),
    )?;
    print_private_batch_metrics(shape, metrics);
    report.phase_end()?;

    report.phase_start("agg_prove")?;
    let proof = prover.aggregate(PrivateBatchInputs {
        leaf_proofs,
        outputs: Vec::new(),
        volume_fee_bps: 0,
    })?;
    report.phase_end()?;

    if release_after {
        report.release_memory("after_agg")?;
    }
    Ok(proof)
}

pub fn build_agg_circuit_only(
    leaf: &LeafContext,
    shape: PrivateBatchShape,
    agg_config: CircuitConfig,
    report: &mut PhaseReport,
) -> Result<()> {
    report.phase_start("build_agg_circuit_only")?;
    let (_, metrics) = PrivateBatchProver::new_with_metrics(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        shape,
        leaf.dummy_proof.clone(),
    )?;
    print_private_batch_metrics(shape, metrics);
    report.phase_end()?;
    Ok(())
}
