# qp-wormhole-circuit-builder

CLI to generate Wormhole circuit binaries for proving and verification.

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs <N> [--num-layer0-proofs <M>] --output generated-bins
```

Produces prover and verifier binaries for a given aggregation shape (number of leaf proofs and number of inner proofs for layer0 and layer1 respectively). Use the generated artifacts with [qp-wormhole-prover] and [qp-wormhole-verifier] to run proofs at scale.

## Usage

```text
qp-wormhole-circuit-builder --num-leaf-proofs <N> [--num-layer0-proofs <N>] [--output <DIR>] [--skip-prover] 
```

## License

MIT

[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
