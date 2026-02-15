# qp-wormhole-aggregator

Aggregates multiple Wormhole ZK proofs into a single proof (tree aggregation).

Takes a batch of leaf proofs from the Wormhole circuit and produces one aggregated proof via a configurable tree (branching factor and depth). Uses [qp-wormhole-circuit], [qp-wormhole-prover], and [qp-wormhole-verifier] under the hood.

## License

MIT

[qp-wormhole-circuit]: https://crates.io/crates/qp-wormhole-circuit
[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
