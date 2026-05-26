//! Pipeline phases under measurement:
//!   1. build leaf circuit (extract prover data, common, verifier_only, targets, dummy proof)
//!   2. generate N leaf proofs sequentially (reusing the prover circuit data)
//!   3. build the layer-0 aggregation circuit
//!   4. commit + prove the aggregation
//!
//! Uses dummy circuit inputs so the workload is self-contained.

use anyhow::Result;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_aggregator::dummy_proof::load_dummy_proof;
use wormhole_aggregator::layer0::prover::Layer0AggregationProver;
use wormhole_aggregator::{build_dummy_circuit_inputs, generate_dummy_proof};
use wormhole_circuit::circuit::circuit_logic::{CircuitTargets, WormholeCircuit};
use wormhole_prover::{fill_witness, WormholeProver};
use zk_circuits_common::circuit::{C, D, F};

use crate::report::PhaseReport;

pub struct LeafContext {
    pub common: CommonCircuitData<F, D>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
    /// Prover for generating real leaf proofs (reused across multiple proofs).
    pub prover: Option<WormholeProver>,
    /// Circuit targets for witness filling (cloned for each proof).
    pub targets: CircuitTargets,
}

pub fn build_leaf_context(
    leaf_cfg: CircuitConfig,
    report: &mut PhaseReport,
) -> Result<LeafContext> {
    report.phase_start("build_leaf_circuit")?;
    let circuit = WormholeCircuit::new(leaf_cfg.clone());
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();
    let dummy_bytes = generate_dummy_proof(&circuit_data, &targets)?;

    let verifier_data = circuit_data.verifier_data();
    let common = verifier_data.common.clone();
    let verifier_only = verifier_data.verifier_only.clone();
    drop(circuit_data);
    let dummy_proof = load_dummy_proof(dummy_bytes, &common)?;

    // Build the prover once for reuse
    let prover = WormholeProver::new(leaf_cfg);
    report.phase_end()?;

    Ok(LeafContext {
        common,
        verifier_only,
        dummy_proof,
        prover: Some(prover),
        targets,
    })
}

pub fn generate_leaf_proof(
    ctx: &mut LeafContext,
    idx: usize,
    release_after: bool,
    report: &mut PhaseReport,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    report.phase_start(&format!("gen_leaf_proof[{}]", idx))?;

    let inputs = build_dummy_circuit_inputs()?;

    // Take the prover, use it, then put it back
    let prover = ctx
        .prover
        .take()
        .ok_or_else(|| anyhow::anyhow!("leaf prover already consumed"))?;

    // Fill witness directly using the prover's circuit_data
    let mut pw = PartialWitness::new();
    fill_witness(&mut pw, &inputs, &ctx.targets)?;

    let proof = prover
        .circuit_data
        .prove(pw)
        .map_err(|e| anyhow::anyhow!("Failed to prove: {}", e))?;

    // Restore prover for next use (it still has circuit_data intact)
    ctx.prover = Some(prover);

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
