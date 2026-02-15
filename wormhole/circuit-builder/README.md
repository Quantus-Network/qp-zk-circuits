# qp-wormhole-circuit-builder

CLI to generate Wormhole circuit binaries for proving and verification.

Produces prover and verifier binaries for a given aggregation tree shape (branching factor and depth). Use the generated artifacts with [qp-wormhole-prover] and [qp-wormhole-verifier] to run proofs at scale.

## Usage

```text
qp-wormhole-circuit-builder --branching-factor <N> --depth <D> [--output <DIR>] [--skip-prover]
```

## License

MIT

[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
