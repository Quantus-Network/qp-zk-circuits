# qp-wormhole-circuit-builder

CLI to generate Wormhole circuit binaries for proving and verification.

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs <N> [--num-private-batch-proofs <M>] --output generated-bins
```

Produces verifier binaries (plus the dummy proofs used for padding) for a given aggregation shape (number of leaf proofs and number of inner proofs for private_batch and public_batch respectively). Use the generated artifacts with the aggregator provers and [qp-wormhole-verifier] to run proofs at scale.

Note: no circuit emits a `prover.bin`. [qp-wormhole-prover], `PrivateBatchProver`, and `PublicBatchProver` always rebuild their circuits from source, because a poisoned prover artifact could exfiltrate witness data through the proof's public-input list. `--skip-prover` therefore only affects the dummy private-batch proof used for public-batch padding (which requires a proving run to generate).

## Usage

```text
qp-wormhole-circuit-builder --num-leaf-proofs <N> [--num-private-batch-proofs <N>] [--output <DIR>] [--skip-prover]
```

## License

MIT

[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
