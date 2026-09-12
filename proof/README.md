# qp-zk-circuits-proof

Shared, bounded decoding of uncompressed Plonky2 proofs. The `verifier` and
`prover` features expose the same decoder for the two upstream proof types.
Verifier decoding supports `no_std` without linking the prover.

Pass trusted common circuit data. The decoder checks the public-input count
against that circuit and the remaining bytes before allocating public inputs,
and rejects noncanonical public inputs and trailing bytes. Deserialization
does not establish validity: cryptographically verify the returned proof.
