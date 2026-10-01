//! Measure actual circuit/GPU initialization, without generating a proof.
use anyhow::{Context, Result};
use qp_wormhole_aggregator::common::utils::{
    canonical_leaf_verifier_data, canonical_private_batch_verifier_data,
};
use qp_wormhole_aggregator::public_batch::circuit::circuit_logic::PublicBatchCircuit;
use qp_wormhole_gpu::{DeviceContext, PreparationOptions, PreparedCircuit, ProofWorkspace};
use std::time::Instant;
use zk_circuits_common::circuit::wormhole_public_batch_circuit_config;

fn main() -> Result<()> {
    let arity = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "53".into())
        .parse::<usize>()
        .context("invalid public-batch arity")?;
    let start = Instant::now();
    eprintln!("Building canonical leaf and seven-slot private verifier data...");
    let leaf = canonical_leaf_verifier_data();
    let private = canonical_private_batch_verifier_data(&leaf, 7)?;
    eprintln!("Building arity-{arity} public circuit...");
    let circuit = PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private.common,
        &private.verifier_only,
        arity,
        7,
    )?
    .build_circuit();
    println!(
        "CPU circuit preparation: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    let start = Instant::now();
    let context = futures::executor::block_on(DeviceContext::new())?;
    println!(
        "GPU device initialization: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    println!("Adapter: {:?}", context.adapter_info());
    eprintln!("Preparing fixed buffers, FFT tables and actual-circuit quotient pipelines...");
    let start = Instant::now();
    let prepared = PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())?;
    println!(
        "GPU circuit preparation: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    let timings = prepared.timings();
    println!("Shared pipelines: {:.3}s", timings.kernels.as_secs_f64());
    println!(
        "FFT/commitment plans and tables: {:.3}s",
        timings.fft_tables.as_secs_f64()
    );
    println!(
        "Fixed oracle and wire-map upload: {:.3}s",
        timings.fixed_data.as_secs_f64()
    );
    println!(
        "Permutation preparation: {:.3}s",
        timings.permutation.as_secs_f64()
    );
    println!(
        "Specialized quotient preparation: {:.3}s",
        timings.quotient.as_secs_f64()
    );
    println!(
        "Trace rows: {}; LDE rows: {}; quotient rows: {}; quotient LDE step: {}",
        prepared.degree(),
        prepared.evaluation_rows(),
        prepared.quotient_rows(),
        prepared.quotient_evaluation_step()
    );
    println!(
        "Witness upload per proof: {} bytes",
        prepared.witness_upload_bytes()
    );
    let workspace = ProofWorkspace::prepare(&context, prepared.wire_workspace_field_counts())?;
    println!(
        "Wire-stage mutable buffer plan: {} bytes",
        workspace.allocated_bytes()
    );
    println!("No proof generated.");
    Ok(())
}
