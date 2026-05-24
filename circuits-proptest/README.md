# circuits-proptest

Property-based tests for Quantus ZK circuit gadgets.

Tests are organized around the [`FormalCircuit`](https://blog.zksecurity.xyz/posts/clean/)
pattern: each gadget has an `assumptions` (input domain), a `spec` (pure Rust reference),
and `soundness` / `completeness` properties. We verify these by building a tiny circuit
around the gadget under test and running the actual Plonky2 prover — accept iff `spec`
holds.

## Running

```sh
cargo test -p circuits-proptest
```

Proving is CPU-heavy; the workspace `Cargo.toml` raises `opt-level = 3` for the
`proptest` and `rand_chacha` packages so test cases generate quickly even in `cargo test`.
Tune sample counts via the `PROPTEST_CASES` env var:

```sh
PROPTEST_CASES=8 cargo test -p circuits-proptest -- --nocapture
```

## Layout

- `src/strategies.rs` — reusable `Strategy` generators (Goldilocks felts, bounded
  unsigned ints, `n_log` choices, edge-case-biased values).
- `src/harness.rs` — `prove_gadget` runner that builds a one-gate-batch circuit around
  a gadget, fills the witness, and reports prover success/failure.
- `tests/<gadget>.rs` — one file per gadget under test. Each file declares its
  assumptions, spec, and the soundness/completeness properties.

## Adding a new gadget

1. If the gadget under test is embedded in a larger circuit, factor it into a
   public function in its source crate so the harness can call it directly.
2. Add a `tests/<gadget>.rs` file that:
   - imports `circuits_proptest::{harness, strategies}`,
   - defines a `spec_*` pure-Rust function,
   - writes one `proptest! { #[test] fn soundness(...) }` and
     `proptest! { #[test] fn completeness(...) }` block.
3. Reuse strategies from `circuits_proptest::strategies` — do not re-derive.
