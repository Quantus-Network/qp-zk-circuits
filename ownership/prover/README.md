# qp-ownership-prover

Prover for the wormhole-address ownership circuit.

Typical usage:

1. Build a fresh [`OwnershipProver`](OwnershipProver) (the circuit is small
   and is always constructed from source).
2. Create [`CircuitInputs`](ownership_circuit::inputs::CircuitInputs) from a
   secret and a claim account.
3. [`commit`](OwnershipProver::commit) the inputs and [`prove`](OwnershipProver::prove).

## License

MIT
