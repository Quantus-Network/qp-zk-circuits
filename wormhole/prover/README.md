# qp-wormhole-prover

Prover logic for the Wormhole circuit.

This module provides the `WormholeProver` type, which allows committing inputs to the circuit
and generating a zero-knowledge proof using those inputs.

The typical usage flow involves:

1. Initializing the prover (e.g., via `WormholeProver::default` or `WormholeProver::new`).
2. Creating user inputs with `CircuitInputs`.
3. Committing user inputs using `WormholeProver::commit`.
4. Generating a proof using `WormholeProver::prove`.

## Example

```rust
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use plonky2::plonk::circuit_data::CircuitConfig;

fn main() -> anyhow::Result<()> {
  // Create inputs
  let inputs = CircuitInputs {
      private: PrivateCircuitInputs {
          secret: vec![1u8; 32],
          funding_nonce: 0,
          funding_account: SubstrateAccount::new(&[2u8; 32])?,
          storage_proof: vec![],
          unspendable_account: UnspendableAccount::new(&[1u8; 32]),
      },
      public: PublicCircuitInputs {
          funding_amount: 1000,
          nullifier: Nullifier::new(&[1u8; 32], 0, &[2u8; 32]),
          root_hash: [0u8; 32],
          exit_account: SubstrateAccount::new(&[2u8; 32])?,
      },
  };

  let config = CircuitConfig::standard_recursion_config();
  let prover = WormholeProver::new(config);
  let proof = prover.commit(&inputs)?.prove()?;
  Ok(())
}
```

## License

MIT
