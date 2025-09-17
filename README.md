# ZK Circuits

This repository contains Zero-Knowledge circuits for the Quantus Network, implemented using Plonky2.

## Project Structure

This repository is a Cargo workspace organized to clearly separate different circuit implementations and their components.

- [`common/`](./common/): A crate containing shared code, utilities, and common circuit gadgets used by other circuits in the workspace.
- [`wormhole/`](./wormhole/): This directory contains all crates related to the Wormhole bridge message verification circuit.
  - [`circuit/`](./wormhole/circuit/): The core Plonky2 circuit definition for Wormhole message verification.
  - [`prover/`](./wormhole/prover/): The prover for the Wormhole circuit.
  - [`verifier/`](./wormhole/verifier/): The verifier for the Wormhole circuit.
  - [`aggregator/`](./wormhole/aggregator/): A circuit for recursively aggregating Wormhole proofs.
  - [`tests/`](./wormhole/tests/): Integration tests for the complete Wormhole circuit.
- [`voting/`](./voting/): A separate circuit implementation for a voting system.

## Prerequisites

You can set up your development environment manually or use the provided Nix flake for a reproducible setup.

### Manually

Ensure you have Rust installed. If not, you can install Rust using [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Nix flake

To use the Nix flake, first ensure that you have Nix installed. You can install Nix by running:

```sh
curl -L https://nixos.org/nix/install | sh -s -- --daemon
```

To enter a shell with all the dependencies pre-installed, run:

```sh
nix --experimental-features 'nix-command flakes' develop
```

## Setup

Clone the repository:

```sh
git clone https://github.com/Resonance-Network/zk-circuits
cd zk-circuits
```

## Building & Testing

To build all crates in the workspace:

```sh
cargo build
```

Run the entire test suite:

```sh
cargo test
```

You can also run tests for a specific package, for example, for the `wormhole-circuit`:

```sh
cargo test -p wormhole-circuit
```

To execute the e2e fuzzing tests for the wormhole circuit you will need to spin up a local node then run: 

```sh
# This checks out the quantus api client repo one level up and sets an ENV variable with the path to it. 
source setup_qac.sh
```

```sh
# Then run the fuzzing tests:
cargo test --package tests --lib -- circuit::circuit_data_tests::test_prover_and_verifier_fuzzing --exact --show-output --ignored
```


## Benchmarks

To run prover and verifier benchmarks:

```sh
cargo bench
```

## CI/CD and Release Process

This repository uses an automated CI/CD pipeline for continuous integration and publishing to [crates.io](https://crates.io).

### Continuous Integration

The CI pipeline runs on every push and pull request, performing:

- **Format checks**: Ensures code follows consistent formatting using `rustfmt` and `taplo`
- **Build verification**: Compiles all workspace crates
- **Test execution**: Runs the complete test suite
- **Clippy linting**: Performs static analysis for code quality
- **Documentation**: Builds and verifies documentation
- **Security audit**: Checks for known vulnerabilities in dependencies

### Release Process

The release process is fully automated and follows semantic versioning:

#### 1. Creating a Release Proposal

To initiate a new release, trigger the "Create Release Proposal" workflow manually from the GitHub Actions tab. This workflow:

- Creates a new branch with version updates
- Bumps the workspace version across all crates
- Updates internal dependency versions
- Formats code and commits changes
- Opens a Pull Request with the proposed release

#### 2. Publishing the Release

Once the release proposal PR is reviewed and merged, the "Create Release Tag and Publish" workflow automatically:

- Creates a Git tag for the new version
- Generates a GitHub release with release notes
- Publishes all crates to crates.io in dependency order:
  1. `qp-zk-circuits-common` - Shared utilities and gadgets
  2. `qp-wormhole-circuit` - Core Wormhole circuit implementation
  3. `qp-wormhole-circuit-builder` - Circuit builder utilities
  4. `qp-wormhole-prover` - Wormhole proof generation
  5. `qp-wormhole-verifier` - Wormhole proof verification

### Published Crates

All published crates use the `qp-` prefix and are available on crates.io:

- [`qp-zk-circuits-common`](https://crates.io/crates/qp-zk-circuits-common) - Common utilities and circuit gadgets
- [`qp-wormhole-circuit`](https://crates.io/crates/qp-wormhole-circuit) - Wormhole message verification circuit
- [`qp-wormhole-prover`](https://crates.io/crates/qp-wormhole-prover) - Wormhole circuit prover
- [`qp-wormhole-verifier`](https://crates.io/crates/qp-wormhole-verifier) - Wormhole circuit verifier
- [`qp-wormhole-circuit-builder`](https://crates.io/crates/qp-wormhole-circuit-builder) - Circuit building utilities

### Using Published Crates

To use these crates in your project, add them to your `Cargo.toml`:

```toml
[dependencies]
qp-zk-circuits-common = "0.1.0"
qp-wormhole-circuit = "0.1.0"
qp-wormhole-prover = "0.1.0"
qp-wormhole-verifier = "0.1.0"
```

### Development vs Production Dependencies

During development, the workspace uses local path dependencies for fast iteration. When published to crates.io, these are automatically replaced with version-based dependencies to ensure proper dependency resolution.