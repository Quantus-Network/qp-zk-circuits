use anyhow::Result;
use clap::Parser;
use qp_wormhole_circuit_builder::generate_all_circuit_binaries;

#[derive(Parser, Debug)]
#[command(name = "qp-wormhole-circuit-builder")]
#[command(about = "Generate wormhole circuit binaries for proving and verification")]
struct Args {
    /// Output directory for generated binaries
    #[arg(short, long, default_value = "generated-bins")]
    output: String,

    /// Branching factor for aggregation tree (number of proofs aggregated at each level)
    #[arg(short, long)]
    branching_factor: usize,

    /// Depth of the aggregation tree (num_leaf_proofs = branching_factor^depth)
    #[arg(short, long)]
    depth: u32,

    /// Skip prover binary generation (only generate verifier binaries)
    #[arg(long)]
    skip_prover: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!(
        "Generating circuit binaries with branching_factor={}, depth={} (max {} proofs)",
        args.branching_factor,
        args.depth,
        args.branching_factor.pow(args.depth)
    );

    generate_all_circuit_binaries(
        &args.output,
        !args.skip_prover,
        args.branching_factor,
        args.depth,
    )
}
