# qp-ownership-verifier

Verifier for wormhole-address ownership circuit proofs.

Load pre-built verifier artifacts with `OwnershipVerifier::new_from_bytes`
(keccak256-pinned to the canonical ownership circuit), then pass network proof
bytes to `OwnershipVerifier::verify_bytes`. It returns the verified proof after
checking the encoded public-input count and payload size before allocation.

Existing consumers must replace direct `ProofWithPublicInputs::from_bytes`
calls with `verify_bytes`, or with `decode_proof` followed by verification.
The re-exported upstream type retains its original unbounded decoder.

## License

MIT
