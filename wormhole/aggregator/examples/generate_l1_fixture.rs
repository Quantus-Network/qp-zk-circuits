use anyhow::{anyhow, bail, Context, Result};
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use qp_wormhole_aggregator::aggregator::{AggregationBackend, CircuitType, Layer1Aggregator};
use qp_wormhole_inputs::{BytesDigest, Layer1AggregatedPublicCircuitInputs};
use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use zk_circuits_common::circuit::{C, D, F};

#[derive(Debug)]
struct Args {
    bins_dir: PathBuf,
    out: PathBuf,
    aggregator_address: [u8; 32],
    l0_proofs: Vec<PathBuf>,
}

#[derive(Serialize)]
struct ExpectedExit {
    summed_output_amount: u32,
    exit_account: String,
}

#[derive(Serialize)]
struct ExpectedBundle {
    l0_candidates: Vec<String>,
    l1_aggregate: String,
    aggregator_address: String,
    asset_id: u32,
    volume_fee_bps: u32,
    block_hash: String,
    block_number: u32,
    total_exit_slots: u32,
    exits: Vec<ExpectedExit>,
    nullifiers: Vec<String>,
}

fn default_aggregator_address() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&2u64.to_le_bytes());
    bytes
}

fn usage() -> &'static str {
    "Usage: cargo run --release -p qp-wormhole-aggregator --example generate_l1_fixture -- \\
        --bins-dir <generated-bins> --out <test-data-dir> --l0-proof <proof.hex> \\
        [--l0-proof <proof.hex> ...] [--aggregator-address <32-byte-hex>]"
}

fn parse_hex_digest(value: &str) -> Result<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).context("failed to decode aggregator address hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("aggregator address must be exactly 32 bytes"))
}

fn parse_args() -> Result<Args> {
    let mut raw = env::args().skip(1);
    let mut bins_dir = None;
    let mut out = None;
    let mut aggregator_address = default_aggregator_address();
    let mut l0_proofs = Vec::new();

    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--bins-dir" => {
                bins_dir = Some(PathBuf::from(
                    raw.next()
                        .ok_or_else(|| anyhow!("--bins-dir requires a value"))?,
                ));
            }
            "--out" => {
                out = Some(PathBuf::from(
                    raw.next()
                        .ok_or_else(|| anyhow!("--out requires a value"))?,
                ));
            }
            "--aggregator-address" => {
                aggregator_address = parse_hex_digest(
                    &raw.next()
                        .ok_or_else(|| anyhow!("--aggregator-address requires a value"))?,
                )?;
            }
            "--l0-proof" => {
                l0_proofs.push(PathBuf::from(
                    raw.next()
                        .ok_or_else(|| anyhow!("--l0-proof requires a value"))?,
                ));
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => bail!("unknown argument `{}`\n{}", other, usage()),
        }
    }

    let bins_dir = bins_dir.ok_or_else(|| anyhow!("missing --bins-dir\n{}", usage()))?;
    let out = out.ok_or_else(|| anyhow!("missing --out\n{}", usage()))?;
    if l0_proofs.is_empty() {
        bail!("at least one --l0-proof is required\n{}", usage());
    }

    Ok(Args {
        bins_dir,
        out,
        aggregator_address,
        l0_proofs,
    })
}

fn read_hex_file(path: &Path) -> Result<Vec<u8>> {
    let hex =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    hex::decode(hex.trim()).with_context(|| format!("failed to decode {}", path.display()))
}

fn write_hex_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, format!("{}\n", hex::encode(bytes)))
        .with_context(|| format!("failed to write {}", path.display()))
}

fn digest_hex(digest: &BytesDigest) -> String {
    hex::encode(digest.as_ref())
}

fn parse_l1_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<Layer1AggregatedPublicCircuitInputs> {
    let public_inputs = proof
        .public_inputs
        .iter()
        .map(|felt| felt.to_canonical_u64())
        .collect::<Vec<_>>();
    Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&public_inputs)
}

fn main() -> Result<()> {
    let args = parse_args()?;
    fs::create_dir_all(&args.out)
        .with_context(|| format!("failed to create {}", args.out.display()))?;

    let mut aggregator = Layer1Aggregator::new(
        &args.bins_dir,
        BytesDigest::new_unchecked(args.aggregator_address),
    )
    .context("failed to create layer-1 aggregator")?;
    if args.l0_proofs.len() != aggregator.batch_size() {
        bail!(
            "expected {} L0 proofs for generated binaries, got {}",
            aggregator.batch_size(),
            args.l0_proofs.len()
        );
    }

    let layer0_common = aggregator
        .load_common_data(CircuitType::Leaf)
        .context("failed to load layer-0 common data")?;
    let mut l0_candidate_files = Vec::new();

    for (index, path) in args.l0_proofs.iter().enumerate() {
        let proof_bytes = read_hex_file(path)?;
        let proof =
            ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &layer0_common)
                .map_err(|err| anyhow!("failed to deserialize {}: {}", path.display(), err))?;
        aggregator
            .push_proof(proof)
            .with_context(|| format!("failed to add {}", path.display()))?;

        let file_name = format!("l0_candidate_{}.hex", index);
        write_hex_file(&args.out.join(&file_name), &proof_bytes)?;
        l0_candidate_files.push(file_name);
    }

    let l1_proof = aggregator
        .aggregate()
        .context("failed to prove layer-1 aggregate")?;
    aggregator
        .verify(l1_proof.clone())
        .context("generated layer-1 proof did not verify")?;

    let l1_inputs = parse_l1_inputs(&l1_proof).context("failed to parse layer-1 public inputs")?;
    let l1_proof_bytes = l1_proof.to_bytes();
    write_hex_file(&args.out.join("l1_aggregate.hex"), &l1_proof_bytes)?;

    let expected = ExpectedBundle {
        l0_candidates: l0_candidate_files,
        l1_aggregate: "l1_aggregate.hex".to_string(),
        aggregator_address: digest_hex(&l1_inputs.aggregator_address),
        asset_id: l1_inputs.asset_id,
        volume_fee_bps: l1_inputs.volume_fee_bps,
        block_hash: digest_hex(&l1_inputs.block_data.block_hash),
        block_number: l1_inputs.block_data.block_number,
        total_exit_slots: l1_inputs.total_exit_slots,
        exits: l1_inputs
            .account_data
            .iter()
            .map(|exit| ExpectedExit {
                summed_output_amount: exit.summed_output_amount,
                exit_account: digest_hex(&exit.exit_account),
            })
            .collect(),
        nullifiers: l1_inputs.nullifiers.iter().map(digest_hex).collect(),
    };
    fs::write(
        args.out.join("expected_bundle.json"),
        serde_json::to_string_pretty(&expected)?,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            args.out.join("expected_bundle.json").display()
        )
    })?;

    println!(
        "Wrote {} L0 candidate(s) and one L1 aggregate to {}",
        expected.l0_candidates.len(),
        args.out.display()
    );
    Ok(())
}
