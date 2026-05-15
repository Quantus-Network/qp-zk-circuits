use anyhow::{bail, Result};
use clap::Parser;
use qp_wormhole_circuit_builder::{generate_all_circuit_binaries, CircuitBinsConfig};
use wormhole_aggregator::MAX_PROOF_COUNT;

#[derive(Parser, Debug)]
#[command(name = "qp-wormhole-circuit-builder")]
#[command(about = "Generate wormhole circuit binaries for proving and verification")]
struct Args {
    /// Output directory for generated binaries
    #[arg(short, long, default_value = "generated-bins")]
    output: String,

    /// Number of leaf proofs aggregated into a single layer-0 proof (must be 1-1024)
    #[arg(short, long)]
    num_leaf_proofs: usize,

    /// Number of inner layer0 proofs aggregated into a single layer-1 proof (must be 1-1024 if specified)
    /// Omit this flag to only generate layer-0 artifacts.
    #[arg(short, long)]
    num_layer0_proofs: Option<usize>,

    /// Skip prover binary generation (only generate verifier binaries)
    #[arg(long)]
    skip_prover: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate proof counts upfront with clear error messages
    if args.num_leaf_proofs == 0 || args.num_leaf_proofs > MAX_PROOF_COUNT {
        bail!(
            "num_leaf_proofs must be between 1 and {} (got {})",
            MAX_PROOF_COUNT,
            args.num_leaf_proofs
        );
    }
    if let Some(n) = args.num_layer0_proofs {
        if n == 0 || n > MAX_PROOF_COUNT {
            bail!(
                "num_layer0_proofs must be between 1 and {} (got {})",
                MAX_PROOF_COUNT,
                n
            );
        }
    }

    // Double-check config is valid (this also validates the combination)
    CircuitBinsConfig::new(args.num_leaf_proofs, args.num_layer0_proofs)?;

    println!(
        "Generating circuit binaries (num_leaf_proofs={}, num_layer0_proofs={})",
        args.num_leaf_proofs,
        args.num_layer0_proofs.unwrap_or(0),
    );

    generate_all_circuit_binaries(
        &args.output,
        !args.skip_prover,
        args.num_leaf_proofs,
        args.num_layer0_proofs,
    )
}
