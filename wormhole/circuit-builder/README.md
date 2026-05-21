# qp-wormhole-circuit-builder

CLI to generate Wormhole circuit binaries for proving and verification.

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs 16 [--num-layer0-proofs <M>] --output generated-bins
```

Produces prover and verifier binaries for the fixed 16-leaf compact-child layer-0 topology and optional layer-1 aggregation. Use `--skip-prover` to emit verifier-only artifacts; proving APIs require the matching prover files.

## Usage

```text
qp-wormhole-circuit-builder --num-leaf-proofs 16 [--num-layer0-proofs <N>] [--output <DIR>] [--skip-prover]
```

Layer-0 output includes `inner_common.bin`, `inner_verifier.bin`, `inner_targets.bin`, `outer_common.bin`, `outer_verifier.bin`, `outer_targets.bin`, and the corresponding prover files unless skipped. The outer artifacts are also written as `aggregated_*` aliases for existing layer-1 and verifier consumers.

## License

MIT

[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
