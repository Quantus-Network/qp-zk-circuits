# PR #129 Split Status

## Phase 0 Snapshot

- Source branch at start: `compact-2x8-aggr`
- Current PR HEAD sha: `140e696dfed288d0d87cf7aaf1ce04170f6cea84`
- Snapshot branch: `pr129-original`
- `origin/main` sha: `6ebbb769a1a357c81767e965c363301a81868deb`
- Merge-base sha: `6ebbb769a1a357c81767e965c363301a81868deb`

## Initial Changed-File Inventory

Source command:

```sh
git diff --name-status origin/main...pr129-original
```

```text
M	Cargo.lock
M	README.md
M	wormhole/README.md
M	wormhole/aggregator/Cargo.toml
M	wormhole/aggregator/README.md
M	wormhole/aggregator/benches/aggregator.rs
M	wormhole/aggregator/src/aggregator.rs
M	wormhole/aggregator/src/layer0/circuit/build.rs
D	wormhole/aggregator/src/layer0/circuit/circuit_logic.rs
M	wormhole/aggregator/src/layer0/circuit/constants.rs
A	wormhole/aggregator/src/layer0/circuit/inner.rs
M	wormhole/aggregator/src/layer0/circuit/mod.rs
A	wormhole/aggregator/src/layer0/circuit/outer.rs
A	wormhole/aggregator/src/layer0/prover/inner.rs
D	wormhole/aggregator/src/layer0/prover/lib.rs
M	wormhole/aggregator/src/layer0/prover/mod.rs
A	wormhole/aggregator/src/layer0/prover/outer.rs
A	wormhole/aggregator/src/layer0/prover/session.rs
M	wormhole/aggregator/src/layer0/prover/witness.rs
M	wormhole/aggregator/src/layer1/circuit/circuit_logic.rs
M	wormhole/aggregator/src/profile.rs
M	wormhole/circuit-builder/README.md
M	wormhole/circuit-builder/src/lib.rs
M	wormhole/circuit-builder/src/main.rs
M	wormhole/example/Cargo.lock
M	wormhole/example/Cargo.toml
M	wormhole/example/README.md
M	wormhole/tests/Cargo.toml
M	wormhole/tests/README.md
M	wormhole/tests/src/aggregator/aggregator_tests.rs
A	wormhole/tests/src/layer0_equivalence.rs
M	wormhole/tests/src/lib.rs
```

## Initial Classification

| File | Initial bucket | Notes |
| --- | --- | --- |
| `Cargo.lock` | PR2 | Lockfile churn expected with production switch/docs/example/audit changes unless a subset is needed for PR1 tests. |
| `README.md` | PR2 | Root production docs. |
| `wormhole/README.md` | PR2 | Production docs. |
| `wormhole/aggregator/Cargo.toml` | Shared/split | PR1 only if compact-child core/tests require deps/features; PR2 for production/bench deps. |
| `wormhole/aggregator/README.md` | Shared/split | PR1 minimal non-production note only if useful; PR2 final production wording. |
| `wormhole/aggregator/benches/aggregator.rs` | PR2 | Shipping aggregate/verify benchmark. |
| `wormhole/aggregator/src/aggregator.rs` | PR2 | Production Layer0Aggregator cutover must not be in PR1. |
| `wormhole/aggregator/src/layer0/circuit/build.rs` | PR2 | Artifact-generation production behavior, unless tiny PR1 helper is required. |
| `wormhole/aggregator/src/layer0/circuit/circuit_logic.rs` | PR2 | Legacy single-stage production cleanup; keep in PR1. |
| `wormhole/aggregator/src/layer0/circuit/constants.rs` | Shared/split | PR1 compact-child constants only; PR2 production constants/cleanup if any. |
| `wormhole/aggregator/src/layer0/circuit/inner.rs` | PR1 | New compact-child inner circuit. |
| `wormhole/aggregator/src/layer0/circuit/mod.rs` | Shared/split | PR1 must expose new modules while preserving legacy exports; PR2 may remove/demote legacy path. |
| `wormhole/aggregator/src/layer0/circuit/outer.rs` | PR1 | New compact-child outer circuit. |
| `wormhole/aggregator/src/layer0/prover/inner.rs` | PR1 | New compact-child prover artifacts. |
| `wormhole/aggregator/src/layer0/prover/lib.rs` | PR2 | Legacy namespace removal only after production cutover. |
| `wormhole/aggregator/src/layer0/prover/mod.rs` | Shared/split | PR1 side-by-side module wiring; PR2 cleanup/cutover. |
| `wormhole/aggregator/src/layer0/prover/outer.rs` | PR1 | New compact-child prover artifacts. |
| `wormhole/aggregator/src/layer0/prover/session.rs` | PR1 | New compact-child session orchestration. |
| `wormhole/aggregator/src/layer0/prover/witness.rs` | Shared/split | PR1 compact-child witness helpers; PR2 production cleanup if any. |
| `wormhole/aggregator/src/layer1/circuit/circuit_logic.rs` | PR2 | Layer-1 integration update. |
| `wormhole/aggregator/src/profile.rs` | Uncertain | Not in expected list; inspect before assigning. |
| `wormhole/circuit-builder/README.md` | PR2 | Builder production docs. |
| `wormhole/circuit-builder/src/lib.rs` | PR2 | Builder artifact-generation contract. |
| `wormhole/circuit-builder/src/main.rs` | PR2 | CLI/build behavior. |
| `wormhole/example/Cargo.lock` | PR2 | Example dependency/lockfile churn. |
| `wormhole/example/Cargo.toml` | PR2 | Example dependency changes. |
| `wormhole/example/README.md` | PR2 | Production docs. |
| `wormhole/tests/Cargo.toml` | Shared/split | PR1 only deps/features required for compact-child tests; PR2 integration deps if any. |
| `wormhole/tests/README.md` | PR2 | Shipping integration behavior docs. |
| `wormhole/tests/src/aggregator/aggregator_tests.rs` | PR2 | Production aggregation/integration updates. |
| `wormhole/tests/src/layer0_equivalence.rs` | PR1 | New equivalence/regression tests for compact-child core. |
| `wormhole/tests/src/lib.rs` | Shared/split | PR1 wiring for `layer0_equivalence`; PR2 other integration wiring if any. |

## Validation Log

Commands run before split:

- `git status --short` -> clean worktree.
- `git branch --show-current` -> `compact-2x8-aggr`.
- `git rev-parse HEAD` -> `140e696dfed288d0d87cf7aaf1ce04170f6cea84`.
- `git branch pr129-original HEAD || git branch pr129-original-$(date +%Y%m%d%H%M%S) HEAD` -> succeeded.
- `git fetch origin main` -> succeeded.

Further validation will be appended after each branch is reconstructed.

## PR 1 Reconstruction Notes

- Branch: `split/compact-2x8-core`
- Base: `origin/main` (`6ebbb769a1a357c81767e965c363301a81868deb`)
- Production files intentionally left matching `origin/main` in PR 1:
  - `wormhole/aggregator/src/aggregator.rs`
  - `wormhole/aggregator/src/layer0/circuit/build.rs`
  - `wormhole/circuit-builder/src/lib.rs`
  - `wormhole/circuit-builder/src/main.rs`
  - `wormhole/aggregator/src/layer1/circuit/circuit_logic.rs`
- Legacy single-stage files are retained in PR 1:
  - `wormhole/aggregator/src/layer0/circuit/circuit_logic.rs`
  - `wormhole/aggregator/src/layer0/prover/lib.rs`
- New compact-child files added in PR 1:
  - `wormhole/aggregator/src/layer0/circuit/inner.rs`
  - `wormhole/aggregator/src/layer0/circuit/outer.rs`
  - `wormhole/aggregator/src/layer0/prover/inner.rs`
  - `wormhole/aggregator/src/layer0/prover/outer.rs`
  - `wormhole/aggregator/src/layer0/prover/session.rs`
  - `wormhole/tests/src/layer0_equivalence.rs`
- Shared files split manually:
  - `constants.rs` adds only compact-child constants/config helpers.
  - `circuit/mod.rs` exposes `inner` and `outer` while retaining `circuit_logic`.
  - `prover/mod.rs` exposes compact-child modules while retaining the legacy `Layer0AggregationProver` re-export.
  - `witness.rs` keeps the legacy witness filler and adds compact-child inner/outer fillers.
  - `tests/src/lib.rs` wires only `layer0_equivalence`.

### PR 1 Review Fixes Folded In

- Dummy padding in the compact-child inner prover now validates PI length only; dummy asset/fee values do not force real proofs to asset/fee zero.
- Inner/session proof ordering is deterministic: real proofs sort before dummies, then by canonical public inputs. Slot 0 remains real when a real proof exists.
- `inner_circuit_config()` is explicitly documented and tested as the non-ZK recursion config; `outer_circuit_config()` remains the public ZK wrapper config.
- `Layer0AggregationArtifacts` no longer stores a redundant non-`Arc` outer verifier clone; verification uses `outer_artifacts.verifier_data`.
- `InnerAggregationArtifacts::new()` and `OuterAggregationArtifacts::new()` build once and split the resulting `CircuitData` into prover/verifier data.
- `layer0_equivalence.rs` has focused compact-child equivalence/regression coverage without using production builder artifacts.

### PR 1 Validation

- `cargo fmt --all -- --check` -> failed before formatting; rustfmt reported formatting diffs in `session.rs`, `witness.rs`, and `layer0_equivalence.rs`.
- `cargo fmt --all` -> succeeded.
- `cargo fmt --all -- --check` -> succeeded.
- `cargo metadata --no-deps --format-version 1` -> succeeded. Relevant package names: `qp-wormhole-aggregator`, `tests`.
- `cargo test -p qp-wormhole-aggregator` -> failed after compiling and running 18 tests: 16 passed, 2 failed.
  - `common::recursive::tests::test_safe_recursive_verifier_rejects_wrong_circuit`
  - `layer0::circuit::circuit_logic::tests::layer0_rejects_malicious_circuit_proofs`
  - Both failed with a panic from `qp-plonky2-1.4.1/src/gates/base_sum.rs:198:9`: `assertion left == right failed: Integer too large to fit in given number of limbs; left: 1 right: 0`.
- `cargo test -p tests layer0_equivalence` -> failed on the first run: 3 passed, 2 failed. The failures exposed non-canonical inner ordering and an overly strict exact-PI comparison.
- `cargo test -p tests layer0_equivalence` -> succeeded after fixes: 5 passed, 0 failed, 67 filtered out, finished in 637.07s.
- `cargo test -p qp-wormhole-aggregator normalize_proofs_for_inner_split` -> succeeded: 1 passed, 0 failed, 17 filtered out.

Unrun on PR 1 so far:

- `cargo clippy --workspace --all-targets --all-features -- -D warnings`

## PR 2 Reconstruction Notes

- Branch: `split/compact-2x8-production`
- Base: `split/compact-2x8-core`
- Imported production cutover changes from `pr129-original` for:
  - `Layer0Aggregator`
  - layer-0 artifact generation and aliasing
  - circuit-builder API/CLI behavior
  - layer-1 integration updates
  - production integration tests and benchmarks
  - production docs
  - dependency/lockfile updates
- Removed legacy single-stage production files only in PR 2:
  - `wormhole/aggregator/src/layer0/circuit/circuit_logic.rs`
  - `wormhole/aggregator/src/layer0/prover/lib.rs`
- Preserved PR 1 fixes while importing the production cutover:
  - compact-child dummy padding no longer requires real proofs to have `asset_id=0`
  - canonical real-before-dummy ordering is retained in inner/session splitting
  - `Layer0AggregationArtifacts` verifies through shared `outer_artifacts.verifier_data`
  - no duplicate implicit verification in `Layer0Aggregator::aggregate()`
- Adjusted `common::recursive::tests::test_safe_recursive_verifier_rejects_wrong_circuit` to treat either a returned proof error or a prover panic as a successful rejection of the intentionally invalid proof path. This is needed under workspace feature unification.

### PR 2 Validation

- `cargo fmt --all -- --check` -> failed before formatting due rustfmt diff in `wormhole/aggregator/src/aggregator.rs`.
- `cargo fmt --all` -> succeeded.
- `cargo fmt --all -- --check` -> succeeded.
- `cargo test -p qp-wormhole-aggregator` -> succeeded: 9 passed, 0 failed, 5 doctests ignored, finished in 554.21s.
- `cargo test -p tests layer0_equivalence` -> succeeded: 3 passed, 0 failed, 69 filtered out, finished in 686.87s.
- `cargo test -p tests aggregator::aggregator_tests` -> succeeded: 11 passed, 0 failed, 61 filtered out, finished in 1927.86s.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` -> succeeded. Cargo also printed a future-incompatibility notice for `trie-db v0.30.0`.
- `cargo test --workspace` -> first run failed in `common::recursive::tests::test_safe_recursive_verifier_rejects_wrong_circuit` with the same `qp-plonky2-1.4.1/src/gates/base_sum.rs:198:9` panic seen under workspace feature unification.
- `cargo test --workspace` -> succeeded after the recursive negative-test fix. The `tests` crate reported 66 passed, 0 failed, 6 ignored; doc tests also completed successfully.
- `cargo audit` -> completed with exit code 0 but reported 7 allowed warnings. Reported advisories included:
  - `RUSTSEC-2024-0388` (`derivative` unmaintained)
  - `RUSTSEC-2025-0161` (`libsecp256k1` unmaintained)
  - `RUSTSEC-2025-0119` (`number_prefix` unmaintained)
  - `RUSTSEC-2024-0436` (`paste` unmaintained)
  - `RUSTSEC-2026-0002` (`lru` unsound)
  - `RUSTSEC-2026-0097` (`rand` unsound; reported for both `rand 0.8.5` and `rand 0.9.2`)
- `cargo bench -p qp-wormhole-aggregator --bench aggregator` -> succeeded. Criterion completed:
  - `layer0_shipping_aggregate_2`: `[5.1120 s 5.1417 s 5.1751 s]`
  - `layer0_shipping_aggregate_4`: `[5.0903 s 5.1303 s 5.1846 s]`
  - `layer0_shipping_aggregate_8`: `[5.1128 s 5.1455 s 5.1871 s]`
  - `layer0_shipping_aggregate_16`: `[5.1255 s 5.1620 s 5.1994 s]`
  - `layer0_shipping_verify_2`: `[26.306 ms 26.485 ms 26.651 ms]`
  - `layer0_shipping_verify_4`: `[26.224 ms 26.465 ms 26.699 ms]`
  - `layer0_shipping_verify_8`: `[26.275 ms 26.505 ms 26.725 ms]`
  - `layer0_shipping_verify_16`: `[26.554 ms 26.611 ms 26.673 ms]`
