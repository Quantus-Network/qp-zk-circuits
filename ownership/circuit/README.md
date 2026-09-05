# qp-ownership-circuit

Plonky2 circuit that proves knowledge of the secret for a wormhole address,
without inclusion, block-header, or nullifier constraints.

The relation is the same address derivation used by the Wormhole spend
circuit: `WA(s) = H(H("wormhole" || s))`. The wormhole address and the
claim destination are public; the secret stays private.

## License

MIT
