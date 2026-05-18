# feat(layer0): add compact-child 2x8 core

## Summary

- Introduces compact-child layer-0 inner/outer circuits and prover/session orchestration.
- Keeps existing production `Layer0Aggregator` path unchanged.
- Adds equivalence/regression tests for the compact-child core.
- Folds in dummy-padding, dummy validation, deterministic ordering, non-ZK inner config, verifier-sharing, and constructor fixes.

## Non-goals

- Does not switch production aggregation.
- Does not update circuit-builder artifact outputs.
- Does not remove old production compatibility path.
- Does not update broad user docs to claim the 2x8 path is shipping.

## Tests

- `cargo fmt --all -- --check` -> failed before formatting; rustfmt reported formatting diffs.
- `cargo fmt --all` -> passed.
- `cargo fmt --all -- --check` -> passed.
- `cargo metadata --no-deps --format-version 1` -> passed.
- `cargo test -p qp-wormhole-aggregator` -> failed: 16 passed, 2 failed in pre-existing recursive negative tests with `qp-plonky2` range-check panics.
- `cargo test -p tests layer0_equivalence` -> failed on first run, then passed after ordering/test fixes: 5 passed, 0 failed.
- `cargo test -p qp-wormhole-aggregator normalize_proofs_for_inner_split` -> passed: 1 passed, 0 failed.

## Follow-up

PR 2 switches production to this core.
