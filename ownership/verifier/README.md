# qp-ownership-verifier

Verifier for wormhole-address ownership circuit proofs.

Load pre-built verifier artifacts with [`OwnershipVerifier::new_from_bytes`]
(keccak256-pinned to the canonical ownership circuit), deserialize a
`ProofWithPublicInputs`, and [`verify`](OwnershipVerifier::verify).

## License

MIT
