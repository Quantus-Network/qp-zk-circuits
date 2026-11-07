//! CLI entry point for trusted CI artifact generation.
//!
//! The build host and `--output` directory are trusted during this run; see
//! `wormhole/THREAT_MODEL.md` for the full boundary (local FS adversary on the
//! builder is out of scope).

use anyhow::Result;
use clap::Parser;
use qp_wormhole_circuit_builder::{generate_all_circuit_binaries, PrivateBatchShape};
use wormhole_aggregator::{production, MAX_PROOF_COUNT, MAX_PUBLIC_BATCH_ARITY};

fn parse_count(s: &str, max: usize) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;
    if n == 0 {
        return Err("value must be at least 1".to_string());
    }
    if n > max {
        return Err(format!("value must be at most {max}"));
    }
    Ok(n)
}

/// Value parser for private-batch dimensions, in range 1..=MAX_PROOF_COUNT
fn parse_proof_count(s: &str) -> Result<usize, String> {
    parse_count(s, MAX_PROOF_COUNT)
}

/// Value parser for the public-batch arity, in range 1..=MAX_PUBLIC_BATCH_ARITY
fn parse_public_batch_arity(s: &str) -> Result<usize, String> {
    parse_count(s, MAX_PUBLIC_BATCH_ARITY)
}

#[derive(Parser, Debug)]
#[command(name = "qp-wormhole-circuit-builder")]
#[command(about = "Generate wormhole circuit binaries for proving and verification")]
struct Args {
    /// Output directory for generated binaries
    #[arg(short, long, default_value = "generated-bins")]
    output: String,

    /// Number of leaf proofs aggregated into a single private-batch proof (must be 1-64)
    // Long-form only: a bare `short` on the two proof-count fields would infer
    // `-n` for both, which clap rejects (panics in debug builds, and silently
    // binds `-n` to the first-declared field in release builds).
    #[arg(long, value_parser = parse_proof_count)]
    num_leaf_proofs: usize,

    /// Number of withdrawal output slots in each private-batch proof (must be 1-64)
    #[arg(long, default_value_t = production::NUM_EXIT_SLOTS, value_parser = parse_proof_count)]
    num_exit_slots: usize,

    /// Number of inner private-batch proofs aggregated into a single public-batch proof (must be 1-256 if specified)
    /// Omit this flag to only generate private-batch artifacts.
    #[arg(long, value_parser = parse_public_batch_arity)]
    num_private_batch_proofs: Option<usize>,

    /// Skip prover binary generation for the batch aggregation circuits (only generate
    /// verifier binaries). The leaf circuit never emits a prover binary: WormholeProver
    /// always builds the leaf circuit from source.
    #[arg(long)]
    skip_prover: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validation is handled by:
    // 1. clap value_parser at arg-parse time (range checks)
    // 2. CircuitBinsConfig::new inside generate_all_circuit_binaries (full validation)

    println!(
        "Generating circuit binaries (num_leaf_proofs={}, num_exit_slots={}, num_private_batch_proofs={})",
        args.num_leaf_proofs,
        args.num_exit_slots,
        args.num_private_batch_proofs.unwrap_or(0),
    );

    generate_all_circuit_binaries(
        &args.output,
        !args.skip_prover,
        PrivateBatchShape::new(args.num_leaf_proofs, args.num_exit_slots),
        args.num_private_batch_proofs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// clap only checks the argument definition via debug assertions inside
    /// `Command::build()`; a duplicate short flag (e.g. two fields inferring
    /// `-n`) panics every debug-build invocation and silently resolves to the
    /// first-declared field in release builds. Run those assertions as a test
    /// so an invalid CLI definition fails CI instead of operators.
    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}
