# qp-ownership-circuit-builder

Generate verifier artifacts (`verifier.bin`, `common.bin`) for the
wormhole-address ownership circuit.

Intended to run on a trusted CI build host. No `prover.bin` is emitted:
[`qp-ownership-prover`] always builds the circuit from source.

## License

MIT

[qp-ownership-prover]: https://crates.io/crates/qp-ownership-prover
