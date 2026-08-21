# qp-wormhole-inputs

Public input types for Wormhole circuit proofs.

Defines the data structures used as public inputs and aggregated outputs for the Wormhole ZK circuit (e.g. `PublicCircuitInputs`, `PublicInputsByAccount`, `BlockData`, `PrivateBatchPublicInputs`). The 22-felt intermediate leaf layout appends the authenticated `input_amount`; the private-batch wrapper consumes it for aggregate fee conservation without forwarding it in aggregate proofs. Used by the Wormhole circuit, prover, verifier, and aggregator crates.

## License

MIT
