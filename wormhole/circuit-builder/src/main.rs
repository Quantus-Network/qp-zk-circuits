use anyhow::Result;
use clap::Parser;
use qp_wormhole_circuit_builder::generate_all_circuit_binaries;

#[derive(Parser, Debug)]
#[command(name = "qp-wormhole-circuit-builder")]
#[command(
    about = "Generate wormhole circuit binaries for proving and verification. The default aggregated output is the shipping 2x8 outer wrapper."
)]
struct Args {
    /// Output directory for generated binaries
    #[arg(short, long, default_value = "generated-bins")]
    output: String,

    /// Retained for API compatibility; shipping aggregated output stays fixed at 16 leaf proofs.
    #[arg(short, long, default_value_t = 16)]
    num_leaf_proofs: usize,

    /// Number of inner layer0 proofs aggregated into a single layer-1 proof.
    /// Omit this flag to skip layer-1 artifact generation.
    #[arg(long)]
    num_layer0_proofs: Option<usize>,

    /// Skip prover binary generation (only generate verifier binaries)
    #[arg(long)]
    skip_prover: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!(
        "Generating circuit binaries (shipping 2x8 aggregated output fixed at 16 leaves, num_leaf_proofs={}, num_layer0_proofs={})",
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
