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
