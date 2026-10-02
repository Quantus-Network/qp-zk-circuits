//! Compare CPU/GPU proving on prepared, populated public-batch fixtures.
//! Usage: public_batch_compare <cpu|gpu> <fixture-dir> [a|b ...]
//! Dataset A is full-0.bin through full-52.bin; B is full-53.bin through full-105.bin.
//! Initialization, input loading and output checks are outside the proof timer.
//! ProvingContext::prove_batch includes admission, witness generation and final verification.
use anyhow::{ensure, Context, Result};
use plonky2::field::types::PrimeField64;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_aggregator::aggregator::PublicBatchAggregator;
use qp_wormhole_aggregator::CircuitBinsConfig;
use qp_wormhole_gpu::{DeviceContext, PreparationOptions};
use qp_wormhole_inputs::{BytesDigest, PrivateBatchPublicInputs, PublicBatchPublicInputs};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Instant};
use zk_circuits_common::circuit::{C, D, F};

type Proof = ProofWithPublicInputs<F, C, D>;
const ARITY: usize = 53;
const LEAVES: usize = 7;

fn values(proof: &Proof) -> Vec<u64> {
    proof
        .public_inputs
        .iter()
        .map(|v| v.to_canonical_u64())
        .collect()
}

fn check_output(proof: &Proof, inputs: &[Proof], address: BytesDigest) -> Result<()> {
    let actual = PublicBatchPublicInputs::try_from_u64_slice(&values(proof), ARITY, LEAVES)?;
    let private = inputs
        .iter()
        .map(|p| PrivateBatchPublicInputs::try_from_u64_slice(&values(p)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        actual.aggregator_address == address,
        "aggregator address mismatch"
    );
    ensure!(actual.asset_id == private[0].asset_id, "asset mismatch");
    ensure!(
        actual.volume_fee_bps == private[0].volume_fee_bps,
        "fee mismatch"
    );
    ensure!(
        actual.block_data == private[0].block_data,
        "block metadata mismatch"
    );
    let accounts: Vec<_> = private
        .iter()
        .flat_map(|p| p.account_data.clone())
        .collect();
    let nullifiers: Vec<_> = private.iter().flat_map(|p| p.nullifiers.clone()).collect();
    ensure!(actual.account_data == accounts, "forwarded exits mismatch");
    ensure!(
        actual.nullifiers == nullifiers,
        "forwarded nullifiers mismatch"
    );
    ensure!(
        actual.nullifiers.iter().collect::<BTreeSet<_>>().len() == ARITY * LEAVES,
        "fixture must contain distinct nullifiers"
    );
    ensure!(
        actual
            .account_data
            .iter()
            .all(|a| a.summed_output_amount > 0),
        "fixture must contain populated exits"
    );
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let backend = args.next().context("expected cpu or gpu backend")?;
    ensure!(
        matches!(backend.as_str(), "cpu" | "gpu"),
        "expected cpu or gpu backend"
    );
    let dir = PathBuf::from(args.next().context("expected fixture directory")?);
    let mut cases: Vec<_> = args.collect();
    if cases.is_empty() {
        cases.push("a".into());
    }
    ensure!(
        cases.iter().all(|c| matches!(c.as_str(), "a" | "b")),
        "expected a or b dataset"
    );
    let config = CircuitBinsConfig::load(&dir)?;
    ensure!(
        config.num_leaf_proofs == LEAVES && config.num_private_batch_proofs == Some(ARITY),
        "expected arity-53, seven-leaf fixtures"
    );
    let address = BytesDigest::try_from([7u8; 32])?;
    let started = Instant::now();
    eprintln!(
        "[start] initializing {backend} aggregator from {}",
        dir.display()
    );
    let mut aggregator = PublicBatchAggregator::new(&dir, address)?;
    let cpu_init = started.elapsed().as_secs_f64();
    let mut device_init = 0.0;
    let mut gpu_init = 0.0;
    if backend == "gpu" {
        let device_started = Instant::now();
        let context = Arc::new(futures::executor::block_on(DeviceContext::new())?);
        device_init = device_started.elapsed().as_secs_f64();
        println!("[adapter] {:?}", context.adapter_info());
        let gpu_started = Instant::now();
        aggregator = aggregator.with_gpu(context, PreparationOptions::default())?;
        gpu_init = gpu_started.elapsed().as_secs_f64();
    }
    println!(
        "[init] {}",
        serde_json::json!({
            "backend":backend, "cpu_circuit_s":cpu_init, "device_s":device_init,
            "gpu_resources_s":gpu_init, "total_s":started.elapsed().as_secs_f64(),
            "threads":rayon::current_num_threads(), "degree_bits":aggregator.public_batch_common().degree_bits(),
            "public_inputs":aggregator.public_batch_common().num_public_inputs,
            "arity":ARITY, "leaves":LEAVES
        })
    );
    let mut datasets = Vec::new();
    for case in &cases {
        let first = if case == "a" { 0 } else { ARITY };
        let inputs = (first..first + ARITY)
            .map(|i| {
                let path = dir.join(format!("full-{i}.bin"));
                Proof::from_bytes(std::fs::read(&path)?, aggregator.private_batch_common())
                    .with_context(|| format!("deserialize {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        datasets.push(inputs);
    }
    let worker = aggregator.proving_context();
    let mut seen = Vec::<(String, Vec<F>)>::new();
    for (case, inputs) in cases.into_iter().zip(datasets) {
        let expected = inputs.clone();
        eprintln!("[sample_start] backend={backend} case={case}");
        let started = Instant::now();
        let proof = worker.prove_batch(inputs)?;
        let seconds = started.elapsed().as_secs_f64();
        check_output(&proof, &expected, address)?;
        if let Some((_, pis)) = seen.iter().find(|(name, _)| *name == case) {
            ensure!(
                *pis == proof.public_inputs,
                "public inputs changed on repeated dataset"
            );
        }
        let public_inputs_hash =
            <C as GenericConfig<D>>::InnerHasher::hash_no_pad(&proof.public_inputs)
                .elements
                .map(|value| value.to_canonical_u64());
        println!(
            "[sample] {}",
            serde_json::json!({
                "backend":backend, "case":case, "seconds":seconds,
                "threads":rayon::current_num_threads(), "proof_bytes":proof.to_bytes().len(),
                "verified":true, "outputs_checked":true,
                "public_inputs_hash":public_inputs_hash
            })
        );
        seen.push((case, proof.public_inputs));
    }
    Ok(())
}
