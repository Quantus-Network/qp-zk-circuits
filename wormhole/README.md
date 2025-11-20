# Wormhole Circuit

## Overview

Provides a Zero-Knowledge circuit that can verify wormhole transactions.

### ZK Circuit Details

**Public Inputs:**

- `funding_amount`: The value or quantity of funds being transacted.
- `nullifier`: A unique, transaction-specific value derived from private information. Its purpose is to prevent double-spending by ensuring that a given set of private inputs can only be used to generate one valid proof.
- `exit_account`: The public address where the `funding_amount` is intended to be sent after the transaction is verified.
- `block_hash`: A commitment (Poseidon2 hash) to the block header fields used inside the circuit.
- `parent_hash`: The parent hash of the transaction’s block. We expose this publicly so proof aggregators can efficiently verify the connection between transactions included in adjacent blocks.
- `block_number`: The block height corresponding to `block_hash`. This is public so the verifier/aggregator can check that it matches the associated header and to know which blocks to connect when aggregating proofs.

**Private Inputs:**

- `secret`: A confidential, randomly generated value unique to the prover, often serving as a primary secret for deriving other transaction components.
- `storage_proof`: A storage proof of a Merkle Patricia trie proving inclusion of the transaction event.
- `transfer_count`: A globally unique ID for a transfer. Gets incremented with each transfer, ensuring that each transaction is unique.
- `funding_account`: The account ID associated with the source of the funds (the sender). Used to derive the nullifier and confirm ownership.
- `state_root`: The state root of the Substrate block (the Merkle-Patricia trie root for the state).
- `extrinsics_root`: The extrinsics root of the block header.
- `digest`: The raw header digest field (110 bytes), encoded injectively into a fixed number of field elements for use inside the circuit.
- `unspendable_account`: An account ID derived from the `secret` that, when hashed, produces a verifiable “burn” (unspendable) address.

> Note: Instead of passing a monolithic `block_header` preimage into the circuit, we pass the structured header fields
> (`parent_hash`, `block_number`, `state_root`, `extrinsics_root`, `digest`) and recompute a Poseidon2 hash from them
> inside the circuit. That hash is constrained to equal the public `block_hash`.

#### Logic Flow

**The circuit does the following**:

1. **Nullifier Derivation**

   - Computes `H(H(salt || secret || transfer_count))`.
   - Compares the derived value against the provided `nullifier` public input.

2. **Unspendable Account Derivation**

   - Computes `H(H(salt || secret))`.
   - Compares the derived value with the provided `unspendable_account`.

3. **Storage Proof Verification**

   - The circuit verifies the `storage_proof` to confirm that a specific leaf (the transfer event) is part of the Merkle Patricia trie with root `state_root`.
   - To verify that the storage proof is valid, the circuit traverses the tree in root-to-leaf order, and for each node:
     1. Compares the expected hash against the hash of the current node (verifies inclusion).
     2. Updates the expected hash to be equal to the hash of the current node.
     3. If this node is the leaf node: additionally verifies that it includes the hash of the leaf inputs (transfer event).

4. **Block Header Commitment Verification**

   The circuit does **not** parse a raw header byte blob; instead, it works over structured header fields and enforces that they are all tied together via a Poseidon2 commitment:

   - Inputs:
     - `parent_hash` (public)
     - `block_number` (public)
     - `state_root` (private)
     - `extrinsics_root` (private)
     - `digest` (private, 110 bytes mapped injectively to field elements)
   - Steps:
     1. **Range-check `block_number`**:  
        The circuit constrains `block_number` to be a 32-bit value to ensure it matches the canonical encoding used outside the circuit.
     2. **Build header preimage**:  
        The above fields are collected into a vector of field elements:
        ```text
        preimage = parent_hash || block_number || state_root || extrinsics_root || digest
        ```
     3. **Poseidon2 hash**:  
        The circuit computes:
        ```text
        computed_hash = Poseidon2Hash(preimage)
        ```
        using `hash_n_to_hash_no_pad_p2::<Poseidon2Hash>`.
     4. **Connect to public `block_hash`**:  
        The circuit enforces:
        ```text
        block_hash == computed_hash
        ```
        where `block_hash` is a public input (`HashOutTarget`).
   
   As a result:
   - Once an on-chain verifier or aggregator checks that the public `block_hash` corresponds to a real block in the underlying chain,
   - all of the internal header fields (`parent_hash`, `block_number`, `state_root`, `extrinsics_root`, `digest`) are cryptographically bound to that real header via Poseidon2.
   - Because the same `state_root` is also used in the storage proof, this ties the storage proof, the header, and the public block commitment together.

## Testing

To run the tests for this circuit, please follow the instructions in the [tests](./tests/) crate.

## Building the Circuit Binary

The core circuit logic can be compiled into a binary artifact (`circuit_data.bin`) that can be used by other parts of the system. This file
must be generated manually after cloning the repository or after making any changes to the circuit logic.

To build the circuit binary, run the following command from the root of the workspace:

```sh
cargo run --release -p circuit-builder
```

This will create a `circuit_data.bin` file in the root of the workspace. You must re-run this command any time you make changes to the files in the `wormhole/circuit` crate to ensure the binary is up-to-date.
