# Wormhole Circuit Tests

This crate contains the Wormhole integration and regression test suites. It includes shipping
layer-0 contract and semantic regression tests, cached-artifact proving tests, and cross-crate
aggregator regressions.

## Running Tests

To run all tests:

```bash
cargo test -p tests
```

To run tests for a specific module or suite:

```bash
# For prover tests
cargo test -p tests prover

# For circuit tests
cargo test -p tests circuit

# For verifier tests
cargo test -p tests verifier

# For aggregator tests
cargo test -p tests aggregator

# For layer-0 contract and semantic regression tests
cargo test -p tests layer0_equivalence
```

The expensive layer-0 proving and semantic regression smokes should be run in release mode:

```bash
cargo test -p tests --release layer0_equivalence::layer0_matches_reference_single_stage_semantics -- --nocapture
cargo test -p tests --release layer0_equivalence::layer0_warm_artifacts_load_and_prove -- --nocapture
cargo test -p tests --release aggregator::aggregator_tests::aggregate_uses_cached_layer0_artifacts -- --nocapture
```

## Running Benchmarks

This crate does not own the restored production layer-0 Criterion bench. Benchmark commands are:

```bash
# Production layer-0 aggregation bench
cargo bench -p qp-wormhole-aggregator --bench aggregator

# Prover bench
cargo bench -p qp-wormhole-prover --bench prover

# Verifier bench
cargo bench -p qp-wormhole-verifier --bench verifier
```

## Adding New Tests

When adding new tests:
1. Place them in the appropriate subdirectory under `src/` matching the crate name they test.
2. Keep cross-crate integration and regression coverage here; crate-local unit tests and benches can stay with their owning crates.
3. Follow the existing test patterns and organization.

## Note

The `layer0_equivalence` module name is retained for continuity, but the current checkout no
longer carries the deleted legacy layer-0 oracle. These tests now validate the shipping contract,
warm-artifact loading, and related regression invariants directly against the production path.
