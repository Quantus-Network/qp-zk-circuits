# qp-wormhole-aggregator

Aggregates Wormhole leaf proofs into recursive proofs.

Production layer-0 aggregation is the compact-child 2x8 topology: two inner non-ZK proofs over 8 leaf slots each, wrapped by one outer ZK proof. Capacity is fixed at 16 leaves. The final public output is 344 felts: 232 semantic felts and 112 zero-tail felts.

Layer-0 requires these artifacts for proving:

- `common.bin`, `verifier.bin`, `dummy_proof.bin`
- `inner_common.bin`, `inner_verifier.bin`, `inner_prover.bin`, `inner_targets.bin`
- `outer_common.bin`, `outer_verifier.bin`, `outer_prover.bin`, `outer_targets.bin`
- `aggregated_common.bin`, `aggregated_verifier.bin`, `aggregated_prover.bin` as outer aliases for legacy consumers

Verifier-only loading requires only the common/verifier files. `Layer0Aggregator` and `Layer0Verifier` cache verifier data at construction; `verify()` uses the cached in-memory verifier.

Zero exit-account digests are reserved for empty output slots. Leaf and aggregation validation enforce that a zero exit account has zero output amount. Compact-child ordering is deterministic and semantic; consumers should not infer original proof order from emitted exit/nullifier order.

## License

MIT

[qp-wormhole-circuit]: https://crates.io/crates/qp-wormhole-circuit
[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
