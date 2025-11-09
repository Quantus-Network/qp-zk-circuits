# Wormhole Circuit

## Overview

Provides a Zero-Knowledge circuit that can verify wormhole transactions.

### ZK Circuit Details

**Public Inputs:**

- `funding_amount`: The value or quantity of funds being transacted.
- `nullifier`: A unique, transaction-specific value derived from private information. Its purpose is to prevent double-spending by ensuring that a given set of private inputs can only be used to generate one valid proof.
- `exit_account`: The public address where the funding_amount is intended to be sent after the transaction is verified.
- `block_hash`: The hash of the substrate block header that the tx was included in
- `parent_hash`: The parent hash of the tx's block. We commit to this as a public input so aggregators can efficiently verify the connection between tx included in adjacent blocks.
This way the verifier needs to only check that the hash of the latest block real. 
- `block_number`: We commit the block number so we can check the verifier can assure that it matches up with the associated block hash during on-chain verification and so aggregators know which blocks to verify connections between.

**Private Inputs:**

- `secret`: A confidential, randomly generated value unique to the prover, often serving as a primary secret for deriving other transaction components.
- `storage_proof`: A storage proof of a Merkle Patricia trie proving inclusion of the transaction event.
- `transfer_count`: A globally unique ID for a transfer. Gets incremented with each transfer, ensuring that each transaction is unique.
- `funding_account`: The private key or identifier associated with the source of the funds, used to derive the nullifier and confirm ownership.
- `root_hash`: The root hash of a Substrate Merkle Patricia storage proof trie.
- `unspendable_account`: A private identifier derived from the secret that, when hashed, provides a verifiable unspendable (burn) address.
- `block_header`: Constant size raw bytes pre-image to the `block_hash`. It contains metadata about the block and 3 fields that we use in the circuit: `parent_hash`, `block_number`, `root_hash`.

#### Logic Flow

**The circuit does the following**:

1. **Nullifier Derivation:**

- Computes `H(H(salt || secret || transfer_count))`.
- Compares the derived value against the provided `nullifier` public input.

2. **Unspendable Account Derivation:**

- Computes `H(H(salt || secret))`
- Compare the derived value with the provided `unspendable_account`.

3. **Storage Proof Verification:**

- The circuit verifies the `storage_proof` to confirm that a specific leaf (the transaction event) is part of the proof.
- To verify that the storage proof is valid, the circuit traverses the tree in root-to-leaf order, and for each node:
  1. Compares the expected hash against the hash of the current node (verifies inclusion).
  2. Updates the expected hash to be equal to the hash of the current node.
  3. If this node is the leaf node: additionally verify that it includes hash of the leaf inputs.

4. **Block Header Verification:**

- The circuit verifies the `block_header` hashes to the committed `block_hash` and parses the `parent_hash`, `block_number`, and `root_hash`. 
- To verify that the block header is valid, the circuit checks the following fields:
  1. Compares the expected `block_hash` against the hash of the `block_header`.
  2. For the `parent_hash` and `root_hash` digest fields in the `block_header`, we extract the 8x32 limb offsets in which they are encoded in the `block_header` at a fixed location. For the `block_number` we extract the 32 bit limb field element from the block_header.
  3. We connect all these extract fields from the 32 byte limb injective encoding of the `block_header` with their corresponding input targets.

## Testing

To run the tests for this circuit, please follow the instructions in the [tests](./tests/) crate.

## Building the Circuit binary

The core circuit logic can be compiled into a binary artifact
(`circuit_data.bin`) that can be used by other parts of the system. This file
must be generated manually after cloning the repository or after making any
changes to the circuit logic.
To build the circuit binary, run the following command from the root of the workspace:

```sh
cargo run --release -p circuit-builder
```

This will create a `circuit_data.bin` file in the root of the workspace. You must re-run this command any time you make changes to the files in the `wormhole/circuit` crate to ensure the binary is up-to-date.
