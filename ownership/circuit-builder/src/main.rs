//! CLI entry point for trusted ownership-circuit artifact generation.

use anyhow::Result;
use clap::Parser;
use qp_ownership_circuit_builder::generate_circuit_binaries;

#[derive(Parser, Debug)]
#[command(name = "qp-ownership-circuit-builder")]
#[command(about = "Generate ownership circuit binaries for verification")]
struct Args {
    /// Output directory for generated binaries
    #[arg(short, long, default_value = "generated-bins")]
    output: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("Generating ownership circuit binaries...");
    generate_circuit_binaries(&args.output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}
