use anyhow::Result;
use qp_wormhole_circuit_builder::generate_circuit_binaries;

fn main() -> Result<()> {
    generate_circuit_binaries("generated-bins", true)
}
