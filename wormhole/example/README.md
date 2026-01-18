# Wormhole circuit usage example

### This example script

- Submits a funded transfer from a dev account to an unspendable account
- Fetches the corresponding on‑chain storage proof
- Assembles the circuit inputs
- Generates a ZK proof for the wormhole transfer circuit

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

### Offline debug mode

If a JSON debug file (configured as `DEBUG_FILE` in the code) exists and you do not pass `--live`, the script will:

- Load `DebugInputs` from that file
- Build `CircuitInputs` from them
- Directly generate a ZK proof without talking to the node

This mode is useful for iterating on circuit/proof generation using a fixed set of inputs.
