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
- `block_number`: The block height corresponding to `block_hash`. This is public so the verifier/aggregator can check that it matches the associated header and enforce the single-block ZK tree constraint in aggregation.

**Private Inputs:**

- `secret`: A confidential, randomly generated value unique to the prover, used to derive the wormhole address and nullifier.
- `transfer_count`: A per-recipient unique ID for a transfer. Gets incremented with each transfer, ensuring that each transaction is unique. Used in nullifier derivation as `H(H(salt || secret || transfer_count))`.
- `input_amount`: The input amount read from the ZK tree leaf (quantized with 0.01 units of precision). The circuit enforces `(output_amount_1 + output_amount_2) * 10000 <= input_amount * (10000 - volume_fee_bps)`.
- `unspendable_account`: The wormhole address derived from the secret (`H(H(salt || secret))`), matching the recipient field in the ZK tree leaf.
- `parent_hash`, `state_root`, `extrinsics_root`, `digest`: Block header fields used to recompute the public `block_hash`.
- `zk_tree_root`: The ZK tree root committed in the block header. Used both in block-hash computation and to verify the Merkle inclusion proof.
- `zk_merkle_siblings`, `zk_merkle_positions`: A 4-ary sorted Poseidon Merkle inclusion proof for the deposit transfer event in the consensus-maintained ZK tree (`pallet-zk-tree`).

> Note: Deposits are visible transfer events on-chain. The circuit does not use Merkle--Patricia storage proofs or encrypted note commitments. Privacy comes from proving knowledge of the secret without revealing which deposit funded the withdrawal.

> Note: Instead of passing a monolithic `block_header` preimage into the circuit, we pass the structured header fields
> (`parent_hash`, `block_number`, `state_root`, `extrinsics_root`, `zk_tree_root`, `digest`) and recompute a Poseidon2 hash from them
> inside the circuit. That hash is constrained to equal the public `block_hash`.

#### Logic Flow

**The circuit does the following**:

1. **Dummy Proof Detection**

   - If `block_hash == 0` and both `output_amount_1 == 0` and `output_amount_2 == 0`, the circuit treats the proof as a dummy and skips the ZK tree proof, header, and nullifier checks. This enables universal dummy proofs for aggregation padding.

2. **Nullifier Derivation**

   - Computes `H(H(salt || secret || transfer_count))`.
   - Compares the derived value against the provided `nullifier` public input.

3. **Wormhole Address Derivation**

   - Computes `H(H(salt || secret))`.
   - Compares the derived value with the provided `unspendable_account`.

4. **ZK Tree Inclusion Proof + Fee Constraint**

   - The circuit verifies a 4-ary sorted Poseidon Merkle proof that a leaf `(to, transfer_count, asset_id, amount)` exists under the block's committed `zk_tree_root`.
   - Leaf hashing uses injective Poseidon encoding; internal nodes sort four child hashes before compact hashing.
   - The circuit constrains `to == unspendable_account`, `transfer_count` matches the witness, and `asset_id` matches the public input.
   - The circuit enforces the fee constraint using `input_amount`, `output_amount_1`, `output_amount_2`, and `volume_fee_bps`.

5. **Block Header Commitment Verification**

   The circuit does **not** parse a raw header byte blob; instead, it works over structured header fields and enforces that they are all tied together via a Poseidon2 commitment:

   - Inputs:
     - `parent_hash` (private)
     - `block_number` (public)
     - `state_root` (private)
     - `extrinsics_root` (private)
     - `zk_tree_root` (private)
     - `digest` (private, 110 bytes mapped injectively to field elements)
   - Steps:
     1. **Range-check `block_number`**:  
        The circuit constrains `block_number` to be a 32-bit value to ensure it matches the canonical encoding used outside the circuit.
     2. **Build header preimage**:  
        The above fields are collected into a vector of field elements:
        ```text
        preimage = parent_hash || block_number || state_root || extrinsics_root || zk_tree_root || digest
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
   - all of the internal header fields (`parent_hash`, `block_number`, `state_root`, `extrinsics_root`, `zk_tree_root`, `digest`) are cryptographically bound to that real header via Poseidon2.
   - Because the same `zk_tree_root` is also used in the ZK tree inclusion proof, this ties the deposit authentication, the header, and the public block commitment together.

## Aggregation System

The aggregator combines `N` leaf proofs into a single proof with a fixed public input layout. Key behaviors:

- **Single-block ZK tree constraint**: All real proofs (non-zero `block_hash`) must reference the same block.
- **Native asset only (current limitation)**: Dummy padding requires `asset_id = 0` on all real proofs in a batch. Non-native assets are not yet supported for privacy-preserving aggregation with dummy padding.
- **Two outputs per proof**: Each leaf supports `exit_account_1`/`output_amount_1` and `exit_account_2`/`output_amount_2`. Aggregation outputs 2\*`N` exit slots.
- **Privacy via dummy hiding**: Proofs are uniformly shuffled before aggregation; the circuit selects reference values from the first non-dummy slot in-circuit, so no slot position is special. Duplicate exit slots are zeroed (both sum and `exit_account`), making them indistinguishable from dummy padding slots.
- **Dynamic dummy proofs**: Dummy proofs are generated on-the-fly for padding. They use sentinel values (`block_hash = 0`, `output_amount_1 = 0`, `output_amount_2 = 0`, `exit_account = 0`) so the leaf circuit can bypass validation. No dummy proof binaries are checked in.
- **Public input types**: Public input parsing and aggregated outputs live in `wormhole/inputs` (`qp-wormhole-inputs`) and are shared by the circuit, prover, verifier, and aggregator.

## Testing

To run the tests for this circuit, please follow the instructions in the [tests](./tests/) crate.

## Building the Circuit Binaries

The circuit builder generates leaf and aggregated circuit binaries alongside a `config.json` with aggregation configuration.
Re-run this after any circuit changes.

The `num_leaf-proofs` and `num-layer0-proofs` parameters control the number of proofs aggregated at each layer. For example, if you want to aggregate 16 leaf proofs per layer-1 proof, and then aggregate 4 layer-1 proofs per layer-2 proof, you would set `num-leaf-proofs` to 16 and `num-layer0-proofs` to 4. The `num-layer0-proofs` param is optional if you only need layer-0 aggregation support. 

To build the circuit binary, run the following command from the root of the workspace:

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs <N> -- --num-layer0-proofs <N> --output generated-bins
```

This creates `common.bin`, `verifier.bin`, `prover.bin` (unless `--skip-prover`), `aggregated_common.bin`, `aggregated_verifier.bin`, `dummy_proof.bin`,
and `config.json` inside `generated-bins/`.
