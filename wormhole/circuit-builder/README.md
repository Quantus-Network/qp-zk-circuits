# qp-wormhole-circuit-builder

CLI to generate Wormhole circuit binaries for proving and verification.

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs <N> [--num-private-batch-proofs <M>] --output generated-bins
```

Produces prover and verifier binaries for a given aggregation shape (number of leaf proofs and number of inner proofs for private_batch and public_batch respectively). Use the generated artifacts with the aggregator provers and [qp-wormhole-verifier] to run proofs at scale.

Note: the leaf circuit only emits verifier artifacts (`common.bin`, `verifier.bin`, `dummy_proof.bin`). [qp-wormhole-prover] always builds the leaf circuit from source, so there is no leaf `prover.bin`; `--skip-prover` only affects the batch aggregation circuits.

## Usage

```text
qp-wormhole-circuit-builder --num-leaf-proofs <N> [--num-private-batch-proofs <N>] [--output <DIR>] [--skip-prover]
```

## License

MIT

[qp-wormhole-prover]: https://crates.io/crates/qp-wormhole-prover
[qp-wormhole-verifier]: https://crates.io/crates/qp-wormhole-verifier
