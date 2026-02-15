# Wormhole circuit usage example

### This example script

- Submits a funded transfer from a dev account to an unspendable account
- Fetches the corresponding on‑chain storage proof
- Assembles the circuit inputs
- Generates a ZK proof for the wormhole transfer circuit
- Supports aggregating multiple proofs into a single proof

### Prerequisites

- `cargo` and the Rust toolchain installed
- A local Quantus dev node running and listening on `ws://localhost:9944`.
    To run a dev node: 
    1. Clone the [Quantus repository](https://github.com/Quantus-Network/chain)
    2. Build the binary and then run the dev node, setting the reward address to any arbitrary account. For example:

    ```bash
    ./target/release/quantus-node --dev --tmp --rewards-address qzpjg55HuN2vLdQerpZwhsGfRn6b4pc8uh4bdEgsYbJNeu8rn
    ```


### Running the example

#### Generate a single proof

Build and run the example binary:

**Note:** This script runs through the full flow of submitting a transfer, generating a proof and verifying it using the alice dev accoun, sending `1` unit of the native test asset `QUAN` (1 with 12 decimal places of precision) to the unspendable account derived from the provided secret.
```bash
cargo run --release --bin wormhole-example -- \
    --live \
    --funding-account alice \
    --secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    --exit-account fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 \
    --funding-amount 1000000000000
```

#### Generate and aggregate in one command

Generate multiple proofs and aggregate them in a single run:

```bash
cargo run --release --bin wormhole-example -- \
    --generate-and-aggregate \
    --funding-account alice \
    --secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    --exit-account fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 \
    --funding-amount 1000000000000 \
    --aggregation-depth 1 \
    --num-proofs 2
```

This mode:
1. Creates multiple transfers in a single batched transaction (same block)
2. Generates a ZK proof for each transfer
3. Aggregates all proofs into a single aggregated proof

#### Aggregate existing proofs

After generating multiple proofs separately, you can aggregate them:

```bash
cargo run --release --bin wormhole-example -- \
    --aggregate \
    --proof-files proof1.hex,proof2.hex,proof3.hex,proof4.hex \
    --aggregated-proof-output aggregated_proof.hex
```

### CLI arguments (live mode)

- `--live`  
    Force live mode (talks to the node). If omitted, the script will run in offline debug mode if a `DEBUG_FILE` exists; otherwise it behaves like live mode.

- `--funding-account <alice|bob|charlie>`  
    Select which pre-funded dev account will send the transfer:
    - `alice` – dev account Alice
    - `bob` – dev account Bob
    - `charlie` – dev account Charlie

- `--secret <64-char-hex>`  
    Secret used to derive the unspendable account and the nullifier. Must be a 64‑character hex string (32 bytes). Example:
    ```
    --secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    ```

- `--exit-account <64-char-hex>`  
    Exit (withdrawal) account where funds will eventually be withdrawn to. Must be a 64‑character hex string (32 bytes). Example:
    ```
    --exit-account fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
    ```

- `--funding-amount <u128>`  
    Amount (in the circuit's base units, set at 12 decimals currently) to transfer to the unspendable account. Requirements:
    - A valid `u128` integer
    - ≥ `1_000_000_000_000`
    Example:
    ```
    --funding-amount 1000000000000
    ```

### CLI arguments (aggregation mode)

- `--aggregate`
    Enable proof aggregation mode. When this flag is set, the binary will aggregate multiple proofs instead of generating a new one.

- `--proof-files <file1,file2,...>`
    Comma-separated list of proof file paths to aggregate. Required when `--aggregate` is set.
    - Maximum number of proofs: branching_factor^depth (configured via `--aggregation-branching-factor` and `--aggregation-depth`)
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

### CLI arguments (generate-and-aggregate mode)

- `--generate-and-aggregate`
    Generate multiple proofs and aggregate them in one run. Combines `--live` and `--aggregate` modes.

- `--num-proofs <n>`
    Number of proofs to generate. Defaults to the number of leaf proofs required by the aggregation tree configuration.

- `--aggregation-depth <n>`
    Tree depth for aggregation (required). Use 1 for minimal aggregation.

- `--aggregation-branching-factor <n>`
    Branching factor for the aggregation tree (required). Number of proofs aggregated at each level.

## Proof Aggregation

The example now supports proof aggregation using a tree-based recursive aggregation scheme. This allows you to:

1. **Batch verification**: Aggregate multiple wormhole transfer proofs into a single proof
2. **Reduced on-chain verification cost**: Verify many transfers with a single proof verification
3. **Privacy preservation**: Aggregate proofs while maintaining zero-knowledge properties

### How it works

The aggregator uses a tree structure (configurable branching factor and depth) to recursively aggregate proofs:
- Configuration must be specified via `--aggregation-branching-factor` and `--aggregation-depth`
- Number of leaf proofs = branching_factor^depth
- Aggregates public inputs by grouping by block and exit account
- Sums funding amounts for the same exit account across multiple proofs
- Collects all nullifiers to prevent double-spending
- Verifies parent-hash linkage between blocks

### Aggregated Public Inputs

The aggregated proof contains:
- Number of unique exit accounts
- Asset ID (enforced to be consistent across all proofs)
- Latest block hash and block number
- For each exit account: summed funding amount and exit account address
- All nullifiers from individual proofs
- Zero-padding to maintain consistent proof size

### Verification

Aggregated proofs can be verified using the verifier binary from the `wormhole-verifier` crate. Note that **aggregated proof verification is currently only supported off-chain** using the verifier binary, not on-chain via the pallet.

### Offline debug mode

If a JSON debug file (configured as `DEBUG_FILE` in the code) exists and you do not pass `--live`, the script will:

- Load `DebugInputs` from that file
- Build `CircuitInputs` from them
- Directly generate a ZK proof without talking to the node

This mode is useful for iterating on circuit/proof generation using a fixed set of inputs.
