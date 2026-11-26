# qp-ownership-inputs

Public input types for wormhole-address ownership circuit proofs.

Defines the 8-felt public-input layout used to claim an airdrop by proving
knowledge of the secret that derives a specific wormhole address:

- `wormhole_address` (4 felts): the address being claimed
- `claim_account` (4 felts): the destination the airdrop is paid to

Used by the ownership circuit, prover, and verifier crates.

## License

MIT
