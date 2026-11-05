# Wormhole Circuit

## Overview

Provides the Wormhole ZK circuit and proof aggregation system for verifying and batching
wormhole transactions.

### ZK Circuit Details

**Public Inputs:**

The leaf circuit is a proof of burn: it authenticates that a deposit of `input_amount` was
made at the committed block and that the prover knows its spend credential. It carries no
outputs; payouts are chosen at the private-batch layer.

- `asset_id`: The asset ID (0 for native token).
- `nullifier`: A transaction-specific value derived from private information (`H(H(salt || secret || transfer_count))`). The circuit proves it is *well-formed* — bound to the deposit being spent — so each deposit event yields exactly one valid nullifier. Actual double-spend prevention (rejecting a nullifier that was already settled) happens **on-chain in the wormhole pallet**, not in the proof; see [Nullifiers and Double-Spend Prevention](#nullifiers-and-double-spend-prevention-security-model).
- `block_hash`: A commitment (Poseidon2 hash) to the block header fields used inside the circuit. All zeros marks a dummy padding proof.
- `block_number`: The block height corresponding to `block_hash`. This is public so the verifier/aggregator can check that it matches the associated header and enforce the single-block storage proof constraint in aggregation.
- `input_amount`: The amount authenticated by the spent ZK-tree leaf, exposed as a `u32` quantized with 0.01 units of precision (human-readable amount × 10^2). On-chain, amounts are stored as `u128` with 12 decimal places; the chain reconstructs this by multiplying by 10^10. This final leaf PI is consumed by the local private-batch wrapper and is not forwarded by private- or public-batch proofs.

**Private Inputs:**

- `secret`: A confidential, randomly generated value unique to the prover, often serving as a primary secret for deriving other transaction components.
- `storage_proof`: A storage proof of a Merkle Patricia trie proving inclusion of the transaction event.
- `transfer_count`: A per-recipient-account unique ID for a transfer. Gets incremented with each transfer, ensuring that each transaction is unique.
- `funding_account`: The account ID associated with the source of the funds (the sender). Used to derive the nullifier and confirm ownership.
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

   - If `block_hash == 0`, the circuit treats the proof as a dummy and skips the storage proof, header, and nullifier checks, and constrains `input_amount == 0`. This enables universal dummy proofs for aggregation padding.

2. **Nullifier Derivation**

   - Computes `H(H(salt || secret || transfer_count))`.
   - Compares the derived value against the provided `nullifier` public input.

3. **Unspendable Account Derivation**

   - Computes `H(H(salt || secret))`.
   - Compares the derived value with the provided `unspendable_account`.

4. **Storage Proof Verification**

   - The circuit verifies the `storage_proof` to confirm that a specific leaf (the transfer event) is part of the Merkle Patricia trie with root `state_root`.
   - To verify that the storage proof is valid, the circuit traverses the tree in root-to-leaf order, and for each node:
     1. Compares the expected hash against the hash of the current node (verifies inclusion).
     2. Updates the expected hash to be equal to the hash of the current node.
     3. If this node is the leaf node: additionally verifies that it includes the hash of the leaf inputs (transfer event).
   - The authenticated `input_amount` is appended to the intermediate leaf public inputs.

5. **Private-Batch Outputs and Fee Constraint**

   - The first aggregation layer takes `M` prover-chosen `(exit_account, amount)` exit slots and the batch `volume_fee_bps` as witnesses, exposes them as public inputs, masks dummy inputs, sums every real leaf, and enforces one settlement-segment inequality:
     `(sum_outputs * 10000) <= (sum_inputs * (10000 - volume_fee_bps))`.
   - Outputs are decoupled from inputs: one burn may be split across many exit slots and many burns may be pooled into one. The input total remains internal to the wrapper.

6. **Block Header Commitment Verification**

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

## Threat model (artifacts & trust boundaries)

Circuit binaries are **CI-generated on a trusted build host**. The adversarial
model for artifact *generation* and for loading attested bins directories is spelled
out in [`THREAT_MODEL.md`](./THREAT_MODEL.md): local filesystem races on the
builder (symlinks, staging TOCTOU, planted FIFOs, etc.) are **out of scope**;
canonical verifier pinning, dummy-template checks, and untrusted client-proof
admission remain **in scope**. Read that document before filing or triaging
findings against `circuit-builder` or artifact I/O.

## Nullifiers and Double-Spend Prevention (Security Model)

A recurring review question is where nullifier *collisions* (reuse of the same nullifier,
i.e. a double spend) are prevented. Short answer: **on-chain, in the wormhole pallet — not
inside any circuit in this repository**. The layers split the work as follows.

### What the circuits prove

- **Leaf circuit**: proves the public `nullifier` is *well-formed*: it equals
  `H(H(salt || secret || transfer_count))` for the same private `secret` that derives the
  unspendable (deposit) account, and the same `transfer_count` that appears in the storage
  proof leaf. This binds the nullifier to exactly one funded deposit event: a prover cannot
  choose the nullifier independently of the deposit it is spending, and one deposit event
  yields exactly one valid nullifier. (Dummy padding proofs — `block_hash == 0`, which
  forces `input_amount == 0` — are exempt from this binding; see below.)
- **Private-batch circuit**: requires real nullifiers to be pairwise distinct within the
  private segment. For dummy slots it substitutes the hash of a fresh random preimage and
  emits the nullifiers in leaf-slot order. The prover shuffles the leaf slots before
  proving, and exit slots are independent witnesses, so the public order reveals nothing
  about which slots are real or which burn funds which payout.
- **Public-batch circuit**: forwards the private-batch public inputs (including all
  nullifiers) verbatim into its own public inputs.

### What the circuits deliberately do NOT prove

No circuit checks that a nullifier is *unused* against chain history. The same
private-batch proof can still appear in two different public batches, and two private
segments in one public batch can overlap. This is by design:

- Uniqueness is a statement about **global, evolving chain state**. A proof is generated at
  some point in time against a snapshot; by the time it settles, other spends may have
  landed. An in-circuit "not yet spent" check would bind each proof to a specific nullifier-set
  state and make proofs race each other (any settlement invalidates every in-flight proof).
- The zk tree is cumulative and clients may prove against any recent block, so the
  aggregation layers cannot know which nullifiers are settled without trusting the operator
  — and aggregators (miners) are explicitly untrusted for soundness.

The circuits' contract is narrower and time-independent: every non-dummy nullifier is
well-formed and bound to a real funded deposit at the committed block, and no real
nullifier repeats within one private segment. Global deduplication remains the settlement
layer's responsibility because only it has authoritative state.

### What the chain enforces (the actual double-spend boundary)

The wormhole pallet (in the chain repository, not here) maintains the persistent set of
settled nullifiers. When an aggregated batch is submitted, the pallet must, for each
nullifier in the proof's public inputs:

1. reject (or skip, see below) any nullifier already present in the settled set, and
2. atomically record the newly settled nullifiers together with executing the corresponding
   exits.

Fee settlement uses the same private-segment boundary as the proof: a public batch must sum
the independently rounded fee of each accepted private segment, not round once over the
combined public-batch output.

A duplicated nullifier — whether across private segments, across two batches in the same
block, or across blocks — settles **at most once**. The private-batch circuit rejects
duplicates within a segment as defense in depth; the pallet remains the consensus boundary
for every case.

A chain-level refinement (tracked separately): for public batches the pallet can settle the
*unused* segments of a batch and skip already-settled nullifiers instead of rejecting the
whole proof, so one front-running miner cannot invalidate another miner's entire batch.

### Dummy-slot nullifiers

Dummy padding slots emit the hash of a **fresh random preimage** as their nullifier. Two
reasons:

- **No spurious collisions**: a fixed dummy nullifier would enter the pallet's settled set
  on first settlement and every later batch containing a dummy slot would collide with it.
  Random 256-bit values make collisions (with each other or with real nullifiers)
  cryptographically negligible.
- **Padding privacy**: dummy slots are indistinguishable from real slots in the nullifier
  region, so observers cannot count how many real spends a batch contains from that region
  alone.

### What the aggregator's duplicate checks are (and are not)

`ProofPool` (miner-side) maintains a pool-wide nullifier index and rejects a proof at
admission if any of its nullifiers is already pooled, and evicts pooled proofs whose
nullifiers settle on-chain (`evict_settled`). These checks are **operational, not
security-critical**: they keep the miner from wasting proving time on batches the pallet
would refuse to settle and prevent duplicate-based pool-capacity DoS. If they were bypassed
entirely, the pallet's nullifier set would still prevent any double spend.

## Aggregation System

The aggregator combines `N` leaf proofs and `M` exit slots into a single proof with a fixed public input layout
`[M, asset_id, volume_fee_bps, block_hash(4), block_number] ++ M × (amount, exit_account(4)) ++ N × nullifier(4)`.
`N` (`--num-leaf-proofs`) and `M` (`--num-exit-slots`) are independent circuit parameters; the production shape is `N = 7`, `M = 16`.
The leaf verifiers dominate the private-batch circuit (about 3.3k gates per leaf), while each exit slot costs roughly one gate plus
five public inputs, so `M` can be raised up to the cap of 64 without changing the circuit degree. Measured degree by `N` with the
production config: `N <= 2` fits `2^14`, `3..=7` fits `2^15`, `8..=16` fits `2^16`, `17+` needs `2^17`. Key behaviors:

- **Single-block storage proof constraint**: All real proofs (non-zero `block_hash`) must reference the same block for storage proofs.
- **Outputs on the batch**: Exit slots are prover-chosen witnesses bound by the batch-wide fee inequality, not per-leaf fields. Slots are forwarded verbatim; unused slots are `(0, zero account)` and several slots may name the same account.
- **Privacy via dummy hiding**: Proofs are uniformly shuffled before aggregation; the circuit selects reference values from the first non-dummy slot in-circuit, so no slot position is special.
- **Dynamic dummy proofs**: Dummy proofs are generated on-the-fly for padding. They use the sentinel `block_hash = 0` (which forces `input_amount = 0`) so the leaf circuit can bypass validation. No dummy proof binaries are checked in.
- **Public input types**: Public input parsing and aggregated outputs live in `wormhole/inputs` (`qp-wormhole-inputs`) and are shared by the circuit, prover, verifier, and aggregator.

## Testing

To run the tests for this circuit, please follow the instructions in the [tests](./tests/) crate.

## Building the Circuit Binaries

The circuit builder generates leaf and aggregated circuit binaries alongside a `config.json` with aggregation configuration.
Re-run this after any circuit changes.

The `--num-leaf-proofs` and `--num-private-batch-proofs` flags control the number of proofs aggregated at each layer, and `--num-exit-slots` sets the number of exit slots per private batch (default 16; `scripts/build-circuits.sh` defaults to `7 16`). For example, if you want to aggregate 16 leaf proofs per private-batch proof, and then aggregate 4 private-batch proofs per public-batch proof, you would set `--num-leaf-proofs` to 16 and `--num-private-batch-proofs` to 4. The `--num-private-batch-proofs` flag is optional if you only need private-batch aggregation support.

To build the circuit binary, run the following command from the root of the workspace:

```sh
cargo run --release -p qp-wormhole-circuit-builder -- --num-leaf-proofs <N> [--num-exit-slots <M>] [--num-private-batch-proofs <N>] --output generated-bins
```

This creates `common.bin`, `verifier.bin`, `private_batch_common.bin`, `private_batch_verifier.bin`, `dummy_proof.bin`,
and `config.json` inside `generated-bins/` (plus the dummy private-batch padding proof unless `--skip-prover`).

Note: no `prover.bin` is emitted for any circuit. The provers (`WormholeProver`,
`PrivateBatchProver`, `PublicBatchProver`) always rebuild their circuits from source;
loading serialized prover artifacts was removed because a poisoned artifact could
exfiltrate private witness data through the proof's public-input list.
