//! Pipeline phases under measurement:
//!   1. build leaf circuit (extract prover data, common, verifier_only, targets, dummy proof)
//!   2. generate N leaf proofs sequentially (reusing the prover circuit data)
//!   3. build the layer-0 aggregation circuit
//!   4. commit + prove the aggregation
//!
//! Uses dummy circuit inputs so the workload is self-contained.

use anyhow::Result;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, ProverCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_aggregator::dummy_proof::load_dummy_proof;
use wormhole_aggregator::layer0::prover::Layer0AggregationProver;
use wormhole_aggregator::{build_dummy_circuit_inputs, generate_dummy_proof};
use wormhole_circuit::circuit::circuit_logic::{CircuitTargets, WormholeCircuit};
use wormhole_prover::fill_witness;
use zk_circuits_common::circuit::{C, D, F};

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

pub fn build_leaf_context(
    leaf_cfg: CircuitConfig,
    report: &mut PhaseReport,
) -> Result<LeafContext> {
    report.phase_start("build_leaf_circuit")?;

    // Build circuit ONCE - extract all data from this single build
    let circuit = WormholeCircuit::new(leaf_cfg);
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();

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

    let inputs = build_dummy_circuit_inputs()?;

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
    let prover = Layer0AggregationProver::new(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        num_leaf_proofs,
        leaf.dummy_proof.clone(),
    );
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
    let _ = Layer0AggregationProver::new(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        num_leaf_proofs,
        leaf.dummy_proof.clone(),
    );
    report.phase_end()?;
    Ok(())
}
