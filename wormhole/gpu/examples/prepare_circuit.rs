//! Prepare a small circuit and allocate a reusable GPU proving workspace.
use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig as C;
use qp_wormhole_gpu::{DeviceContext, PreparationOptions, PreparedCircuit};

fn main() -> Result<()> {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let input = builder.add_virtual_target();
    let square = builder.square(input);
    builder.register_public_input(square);
    let circuit = builder.build::<C>();

    let context = pollster::block_on(DeviceContext::new())?;
    let prepared = PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())?;
    let workspace = prepared.prepare_workspace(&context)?;

    println!(
        "Prepared {} circuit rows and {} bytes of workspace buffers.",
        prepared.degree(),
        workspace.allocated_bytes()
    );
    Ok(())
}
