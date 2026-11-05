# qp-wormhole-inputs

Public input types for Wormhole circuit proofs.

Defines the data structures used as public inputs and aggregated outputs for the Wormhole ZK circuit (e.g. `PublicCircuitInputs`, `PublicInputsByAccount`, `BlockData`, `PrivateBatchPublicInputs`). The 11-felt intermediate leaf layout is a proof of burn (`asset_id`, `nullifier`, `block_hash`, `block_number`, `input_amount`); the private-batch wrapper consumes `input_amount` for aggregate fee conservation without forwarding it in aggregate proofs, and exposes the prover-chosen exit slots and fee rate. Used by the Wormhole circuit, prover, verifier, and aggregator crates.

## License

MIT
