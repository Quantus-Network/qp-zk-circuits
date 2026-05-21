# Wormhole circuit usage example

This example binary can:

- Submit a funded transfer from a dev account to an unspendable account.
- Fetch the corresponding on-chain storage proof.
- Assemble the circuit inputs.
- Generate a ZK proof for the Wormhole transfer circuit.
- Aggregate multiple proofs through the production layer-0 aggregator.

The aggregation path in this example matches the shipping compact-child `2x8` layer-0 design:

- Fixed capacity of `16` leaf proofs per aggregated proof.
- Two non-ZK inner `8`-leaf proofs.
- One final public ZK wrapper proof.
- Fewer than `16` real proofs are padded with the normal shipping dummy-proof flow.

## Prerequisites

- `cargo` and the Rust toolchain installed.
- A local Quantus dev node running and listening on `ws://localhost:9944`.
  To run a dev node:
  1. Clone the [Quantus repository](https://github.com/Quantus-Network/chain).
  2. Build the binary and then run the dev node, setting the reward address to any arbitrary account. For example:

  ```bash
  ./target/release/quantus-node --dev --tmp --rewards-address qzpjg55HuN2vLdQerpZwhsGfRn6b4pc8uh4bdEgsYbJNeu8rn
  ```

## Running the example

### Generate a single proof

Build and run the example binary:

**Note:** This runs through the full flow of submitting a transfer, generating a proof, and
verifying it using the Alice dev account, sending `1` unit of the native test asset `QUAN` (1 with
12 decimal places of precision) to the unspendable account derived from the provided secret.

```bash
cargo run --release --bin wormhole-example -- \
    --live \
    --funding-account alice \
    --secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    --exit-account fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 \
    --funding-amount 1000000000000
```

### Generate and aggregate in one command

Generate multiple proofs and aggregate them in a single run:

```bash
cargo run --release --bin wormhole-example -- \
    --generate-and-aggregate \
    --funding-account alice \
    --secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    --exit-account fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 \
    --funding-amount 1000000000000 \
    --num-leaf-proofs 16 \
    --num-proofs 4
```

This mode:
1. Creates multiple transfers in a single batched transaction (same block).
2. Generates a ZK proof for each transfer.
3. Aggregates all proofs into a single shipping layer-0 proof.

`--num-leaf-proofs` is required here because the example shares the common aggregation config type,
but the production layer-0 path itself is fixed at `16` leaves. Lower `--num-proofs` values are
handled by the normal dummy-padding behavior.

### Aggregate existing proofs

After generating multiple proofs separately, you can aggregate them:

```bash
cargo run --release --bin wormhole-example -- \
    --aggregate \
    --proof-files proof1.hex,proof2.hex,proof3.hex,proof4.hex \
    --aggregated-proof-output aggregated_proof.hex
```

## CLI arguments (live mode)

- `--live`
    Force live mode (talks to the node). If omitted, the script will run in offline debug mode if a `DEBUG_FILE` exists; otherwise it behaves like live mode.

- `--funding-account <alice|bob|charlie>`
    Select which pre-funded dev account will send the transfer:
    - `alice` - dev account Alice
    - `bob` - dev account Bob
    - `charlie` - dev account Charlie

- `--secret <64-char-hex>`
    Secret used to derive the unspendable account and the nullifier. Must be a 64-character hex string (32 bytes). Example:
    ```
    --secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    ```

- `--exit-account <64-char-hex>`
    Exit (withdrawal) account where funds will eventually be withdrawn to. Must be a 64-character hex string (32 bytes). Example:
    ```
    --exit-account fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
    ```

- `--funding-amount <u128>`
    Amount (in the circuit's base units, set at 12 decimals currently) to transfer to the unspendable account. Requirements:
    - A valid `u128` integer
    - `>= 1_000_000_000_000`
    Example:
    ```
    --funding-amount 1000000000000
    ```

## CLI arguments (aggregation mode)

- `--aggregate`
    Enable proof aggregation mode. When this flag is set, the binary will aggregate multiple proofs instead of generating a new one.

- `--proof-files <file1,file2,...>`
    Comma-separated list of proof file paths to aggregate. Required when `--aggregate` is set.
    - Maximum number of proofs: `16`
    - Example:
    ```
    --proof-files proof1.hex,proof2.hex,proof3.hex,proof4.hex
    ```

- `--aggregated-proof-output <path>`
    Output file path for the aggregated proof. Defaults to `aggregated_proof.hex`.
    Example:
    ```
    --aggregated-proof-output my_aggregated_proof.hex
    ```

## CLI arguments (generate-and-aggregate mode)

- `--generate-and-aggregate`
    Generate multiple proofs and aggregate them in one run. Combines `--live` and `--aggregate` modes.

- `--num-leaf-proofs <n>`
    Use `16` for the shipping layer-0 path. This flag is retained to match the shared aggregation
    config type, but it does not reopen layer-0 architecture selection.

- `--num-proofs <n>`
    Number of real proofs to generate. Typical values are `1` through `16`; batches smaller than
    `16` are padded by the shipping layer-0 aggregator.

- `--num-layer0-proofs <n>`
    Accepted for compatibility with the shared aggregation config, but the example's production
    aggregation flow is still the fixed layer-0 `2x8` path.

## Proof Aggregation

The example supports proof aggregation using the same production `Layer0Aggregator` used elsewhere
in the workspace. This allows you to:

1. **Batch verification**: Aggregate multiple Wormhole transfer proofs into a single proof.
2. **Reduced on-chain verification cost**: Verify many transfers with a single proof verification.
3. **Privacy preservation**: Aggregate proofs while maintaining zero-knowledge properties.

### How it works

The aggregator uses the fixed shipping layer-0 structure:

- Two non-ZK inner `8`-leaf proofs feeding one final public wrapper proof.
- Up to `16` real leaf proofs per aggregated proof.
- Dummy padding when fewer than `16` real proofs are provided.
- Aggregates public inputs by grouping by block and exit account.
- Sums funding amounts for the same exit account across multiple proofs.
- Collects all nullifiers to prevent double-spending.
- Verifies parent-hash linkage between blocks.

### Aggregated Public Inputs

The aggregated proof contains:

- Number of unique exit accounts.
- Asset ID (enforced to be consistent across all proofs).
- Latest block hash and block number.
- For each exit account: summed funding amount and exit account address.
- All nullifiers from individual proofs.
- Zero-padding to maintain the stable final proof size.

### Verification

The example verifies the aggregated proof locally with `Layer0Aggregator::verify` after proving.
The resulting proof uses the same stable `aggregated_*` artifact contract that the chain-facing
build pipeline consumes.

### Offline debug mode

If a JSON debug file (configured as `DEBUG_FILE` in the code) exists and you do not pass `--live`, the script will:

- Load `DebugInputs` from that file.
- Build `CircuitInputs` from them.
- Directly generate a ZK proof without talking to the node.

This mode is useful for iterating on circuit/proof generation using a fixed set of inputs.
