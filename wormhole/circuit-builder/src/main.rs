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

    /// Number of leaf proofs aggregated into a single layer-0 proof
    #[arg(short, long)]
    num_leaf_proofs: usize,

    /// Number of inner layer0 proofs aggregated into a single layer-1 proof
    /// Set to none if you only need the layer-0 aggregation circui.
    #[arg(short, long)]
    num_inner_proofs: Option<usize>,

    /// Skip prover binary generation (only generate verifier binaries)
    #[arg(long)]
    skip_prover: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!(
        "Generating circuit binaries (num_leaf_proofs={})",
        args.num_leaf_proofs,
    );

    generate_all_circuit_binaries(
        &args.output,
        !args.skip_prover,
        args.num_leaf_proofs,
        args.num_inner_proofs,
    )
}
