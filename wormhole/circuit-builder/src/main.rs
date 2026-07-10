use anyhow::Result;
use clap::Parser;
use qp_wormhole_circuit_builder::generate_all_circuit_binaries;
use wormhole_aggregator::MAX_PROOF_COUNT;

/// Value parser that validates proof count is in range 1..=MAX_PROOF_COUNT
fn parse_proof_count(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;
    if n == 0 {
        return Err("value must be at least 1".to_string());
    }
    if n > MAX_PROOF_COUNT {
        return Err(format!("value must be at most {MAX_PROOF_COUNT}"));
    }
    Ok(n)
}

#[derive(Parser, Debug)]
#[command(name = "qp-wormhole-circuit-builder")]
#[command(about = "Generate wormhole circuit binaries for proving and verification")]
struct Args {
    /// Output directory for generated binaries
    #[arg(short, long, default_value = "generated-bins")]
    output: String,

    /// Number of leaf proofs aggregated into a single private-batch proof (must be 1-64)
    #[arg(short, long, value_parser = parse_proof_count)]
    num_leaf_proofs: usize,

    /// Number of inner private-batch proofs aggregated into a single public-batch proof (must be 1-64 if specified)
    /// Omit this flag to only generate private-batch artifacts.
    #[arg(short, long, value_parser = parse_proof_count)]
    num_private_batch_proofs: Option<usize>,

    /// Skip prover binary generation (only generate verifier binaries)
    #[arg(long)]
    skip_prover: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validation is handled by:
    // 1. clap value_parser at arg-parse time (range checks)
    // 2. CircuitBinsConfig::new inside generate_all_circuit_binaries (full validation)

    println!(
        "Generating circuit binaries (num_leaf_proofs={}, num_private_batch_proofs={})",
        args.num_leaf_proofs,
        args.num_private_batch_proofs.unwrap_or(0),
    );

    generate_all_circuit_binaries(
        &args.output,
        !args.skip_prover,
        args.num_leaf_proofs,
        args.num_private_batch_proofs,
    )
}
