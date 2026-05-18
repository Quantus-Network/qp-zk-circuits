# perf(layer0): switch production aggregation to compact-child 2x8

## Summary

- Switches production `Layer0Aggregator` to compact-child 2x8.
- Updates artifact generation to emit `inner_*` and `outer_*` artifacts plus stable `aggregated_*` aliases.
- Enforces fixed 16-leaf layer-0 artifact generation.
- Updates layer-1/integration tests, benchmarks, docs, and legacy cleanup.

## Dependency

Stacked on PR 1.

## Compatibility

- Final public contract remains 344 felts = 232 semantic + 112 zero tail.
- Downstream `aggregated_*` aliases remain available.

## Tests

- `cargo fmt --all -- --check` -> passed after running `cargo fmt --all`.
- `cargo test -p qp-wormhole-aggregator` -> passed.
- `cargo test -p tests layer0_equivalence` -> passed.
- `cargo test -p tests aggregator::aggregator_tests` -> passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` -> passed.
- `cargo test --workspace` -> passed after fixing the workspace feature-unified recursive negative test.
- `cargo audit` -> exit code 0 with 7 allowed warnings recorded in `SPLIT_STATUS.md`.
- `cargo bench -p qp-wormhole-aggregator --bench aggregator` -> passed.
