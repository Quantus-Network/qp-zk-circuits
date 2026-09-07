# Ownership Circuit

Proves knowledge of the secret for a wormhole address, without inclusion
proofs, block-header binding, or nullifiers.

The intended use is a mainnet airdrop claim: a user who controlled a
testnet wormhole address proves they know its secret and binds the proof to
the mainnet account that should receive the payout.

## Relation

The address derivation is the same one used by the Wormhole spend circuit:

```text
WA(s) = H(H("wormhole" || s))
```

where `H` is Poseidon2 (`hash_n_to_hash_no_pad`).

**Private input**

- `secret`: the 32-byte wormhole spend secret

**Public inputs (8 felts)**

- `wormhole_address` (4 felts): `WA(s)`, the address being claimed
- `claim_account` (4 felts): the destination the airdrop is paid to

The circuit constrains `WA(secret) == wormhole_address` and registers
`claim_account` as a public input so a stolen proof cannot be submitted to
a different destination.

This circuit does **not** prove that the address received funds, appears in
any tree, or is eligible. The pallet must:

1. Verify the proof against the canonical ownership verifier
2. Check that `wormhole_address` is eligible (snapshot set, Merkle tree, …)
3. Mark the address claimed
4. Pay `claim_account`

## Crates

- [`circuit/`](./circuit/): circuit definition
- [`prover/`](./prover/): proof generation (always built from source)
- [`verifier/`](./verifier/): artifact-loading verifier
- [`inputs/`](./inputs/): public-input types (`no_std`)
- [`circuit-builder/`](./circuit-builder/): generate `verifier.bin` / `common.bin`
- [`tests/`](./tests/): prove / verify integration tests

## License

MIT
