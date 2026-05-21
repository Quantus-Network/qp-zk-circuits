# qp-wormhole-circuit-builder

CLI to generate Wormhole leaf binaries, the shipping layer-0 `2x8` aggregation stack, and
optional layer-1 binaries.

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs 16 --output generated-bins
```

The default aggregated output is the shipping layer-0 outer wrapper, emitted under the stable
chain-facing filenames:

- `aggregated_common.bin`
- `aggregated_verifier.bin`
- `aggregated_prover.bin`
- `aggregated_targets.bin`

It also emits the private internal `inner_*` and `outer_*` binaries needed by the production
`Layer0AggregationProver`.

`--num-leaf-proofs` is retained for API compatibility, but the shipping layer-0 design is fixed at
`16` leaf proofs. `--num-layer0-proofs` only controls optional layer-1 artifact generation; it
does not change the production layer-0 architecture.

Use the generated artifacts with [qp-wormhole-prover], [qp-wormhole-verifier], and
[qp-wormhole-aggregator].

Use `--skip-prover` to emit verifier-only artifacts; proving APIs require the matching prover files.

## Usage

```text
qp-wormhole-circuit-builder [--output <DIR>] [--num-leaf-proofs 16] [--num-layer0-proofs <N>] [--skip-prover]
```

Layer-0 output includes `inner_common.bin`, `inner_verifier.bin`, `inner_targets.bin`, `outer_common.bin`, `outer_verifier.bin`, `outer_targets.bin`, and the corresponding prover files unless skipped. The outer artifacts are also written as `aggregated_*` aliases for existing layer-1 and verifier consumers.

## License

MIT

[qp-wormhole-aggregator]: https://crates.io/crates/qp-wormhole-aggregator
[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
