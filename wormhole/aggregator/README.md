# qp-wormhole-aggregator

Aggregates Wormhole leaf proofs through the production layer-0 aggregation stack.

The shipping layer-0 implementation lives in `src/layer0/**` and uses the fixed compact-child
`2x8` architecture:

- Two non-ZK inner `8`-leaf proofs.
- One final public ZK wrapper proof.
- Fixed batch capacity of `16` leaf proofs.
- Stable final public contract: `344` total felts, `232` semantic felts, `112` zero-tail felts.

`Layer0Aggregator` is the production hot path. It warm-loads cached artifacts from the binaries
directory, pads short batches with the shipping dummy-proof behavior, and returns the same final
`aggregated_*` proof contract used by chain integration.

`Layer1Aggregator` remains available for aggregating full batches of layer-0 proofs when layer-1
artifacts are generated.

By default this crate keeps multithreaded proving enabled through the `multithread` feature, which
turns on `qp-plonky2/parallel` in the shipping build path.

## Benchmarks

The restored Criterion bench for the shipping layer-0 path lives in `benches/aggregator.rs`:

```sh
cargo bench -p qp-wormhole-aggregator --bench aggregator
```

## License

MIT

[qp-wormhole-circuit]: https://crates.io/crates/qp-wormhole-circuit
[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
