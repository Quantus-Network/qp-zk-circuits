# Wormhole Circuit

## Overview

Provides the Wormhole ZK circuit and proof aggregation system for verifying and batching
wormhole transactions.

### ZK Circuit Details

**Public Inputs:**

- `asset_id`: The asset ID (0 for native token).
- `output_amount_1`: The spend amount, exposed as a `u32` quantized with 0.01 units of precision (human-readable amount × 10^2). On-chain, the amount is stored as a `u128` with 12 decimal places; during on-chain verification, we reconstruct this `u128` by multiplying `output_amount_1` by 10^10 (so that 10^2 × 10^10 = 10^12 total decimal precision).
- `output_amount_2`: The optional change amount, also quantized with 0.01 units of precision (set to 0 if unused).
- `volume_fee_bps`: The fee rate in basis points (1 bps = 0.01%). Verified on-chain to match runtime configuration.
- `nullifier`: A unique, transaction-specific value derived from private information. Its purpose is to prevent double-spending by ensuring that a given set of private inputs can only be used to generate one valid proof.
- `exit_account_1`: The public address where `output_amount_1` is intended to be sent.
- `exit_account_2`: The public address where `output_amount_2` is intended to be sent (set to all zeros if unused).
- `block_hash`: A commitment (Poseidon2 hash) to the block header fields used inside the circuit.
- `block_number`: The block height corresponding to `block_hash`. This is public so the verifier/aggregator can check that it matches the associated header and enforce the single-block storage proof constraint in aggregation.

**Private Inputs:**

- `secret`: A confidential, randomly generated value unique to the prover, often serving as a primary secret for deriving other transaction components.
- `storage_proof`: A storage proof of a Merkle Patricia trie proving inclusion of the transaction event.
- `transfer_count`: A per-recipient-account unique ID for a transfer. Gets incremented with each transfer, ensuring that each transaction is unique.
- `funding_account`: The account ID associated with the source of the funds (the sender). Used to derive the nullifier and confirm ownership.
- `input_amount`: The input amount read from storage (quantized with 0.01 units of precision). The circuit enforces `(output_amount_1 + output_amount_2) * 10000 <= input_amount * (10000 - volume_fee_bps)`.
- `state_root`: The state root of the Substrate block (the Merkle-Patricia trie root for the state).
- `extrinsics_root`: The extrinsics root of the block header.
- `digest`: The raw header digest field (110 bytes), encoded injectively into a fixed number of field elements for use inside the circuit.
- `unspendable_account`: An account ID derived from the `secret` that, when hashed, produces a verifiable “burn” (unspendable) address.
- `parent_hash`: The parent hash of the transaction’s block (private, used to compute `block_hash`).

> Note: Instead of passing a monolithic `block_header` preimage into the circuit, we pass the structured header fields
> (`parent_hash`, `block_number`, `state_root`, `extrinsics_root`, `digest`) and recompute a Poseidon2 hash from them
> inside the circuit. That hash is constrained to equal the public `block_hash`.

#### Logic Flow

**The circuit does the following**:

1. **Dummy Proof Detection**

   - If `block_hash == 0` and both `output_amount_1 == 0` and `output_amount_2 == 0`, the circuit treats the proof as a dummy and skips the storage proof, header, and nullifier checks. This enables universal dummy proofs for aggregation padding.

2. **Nullifier Derivation**

   - Computes `H(H(salt || secret || transfer_count))`.
   - Compares the derived value against the provided `nullifier` public input.

3. **Unspendable Account Derivation**

   - Computes `H(H(salt || secret))`.
   - Compares the derived value with the provided `unspendable_account`.

4. **Storage Proof Verification + Fee Constraint**

   - The circuit verifies the `storage_proof` to confirm that a specific leaf (the transfer event) is part of the Merkle Patricia trie with root `state_root`.
   - To verify that the storage proof is valid, the circuit traverses the tree in root-to-leaf order, and for each node:
     1. Compares the expected hash against the hash of the current node (verifies inclusion).
     2. Updates the expected hash to be equal to the hash of the current node.
     3. If this node is the leaf node: additionally verifies that it includes the hash of the leaf inputs (transfer event).
   - The circuit enforces the fee constraint using `input_amount`, `output_amount_1`, `output_amount_2`, and `volume_fee_bps`.

5. **Block Header Commitment Verification**

   The circuit does **not** parse a raw header byte blob; instead, it works over structured header fields and enforces that they are all tied together via a Poseidon2 commitment:

   - Inputs:
     - `parent_hash` (private)
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

## Aggregation System

The aggregator combines `N` leaf proofs into a single proof with a fixed public input layout. Key behaviors:

- **Single-block storage proof constraint**: All real proofs (non-zero `block_hash`) must reference the same block for storage proofs.
- **Two outputs per proof**: Each leaf supports `exit_account_1`/`output_amount_1` and `exit_account_2`/`output_amount_2`. Aggregation outputs 2\*`N` exit slots.
- **Privacy via dummy hiding**: Proofs are shuffled before aggregation while keeping one real proof in slot 0 for reference values. Duplicate exit slots are zeroed (both sum and `exit_account`), making them indistinguishable from dummy padding slots.
- **Dynamic dummy proofs**: Dummy proofs are generated on-the-fly for padding. They use sentinel values (`block_hash = 0`, `output_amount_1 = 0`, `output_amount_2 = 0`, `exit_account = 0`) so the leaf circuit can bypass validation. No dummy proof binaries are checked in.
- **Public input types**: Public input parsing and aggregated outputs live in `wormhole/inputs` (`qp-wormhole-inputs`) and are shared by the circuit, prover, verifier, and aggregator.

## Testing

To run the tests for this circuit, please follow the instructions in the [tests](./tests/) crate.

## Building the Circuit Binaries

The circuit builder generates leaf and aggregated circuit binaries alongside a `config.json` that includes SHA256 hashes for integrity verification.
Re-run this after any circuit changes.

To build the circuit binary, run the following command from the root of the workspace:

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs <N> --output generated-bins
```

This creates `common.bin`, `verifier.bin`, `prover.bin` (unless `--skip-prover`), `aggregated_common.bin`, `aggregated_verifier.bin`, `dummy_proof.bin`,
and `config.json` inside `generated-bins/`. The aggregator will verify the hashes in `config.json` when loading prebuilt binaries.
