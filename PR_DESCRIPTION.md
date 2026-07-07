# Add public-batch (second-layer) aggregation

Branch: `illuzen/next-level-aggregation`

## Summary

Adds a second aggregation layer to the wormhole circuits and renames the aggregation
terminology so the privacy properties are obvious from the names:

| Old name | New name | ZK | Who runs it |
|---|---|---|---|
| layer-0 aggregation | **private batch** | yes | client (local) |
| layer-1 aggregation | **public batch** | no | client or delegated aggregator |

A public batch recursively verifies M private-batch proofs and forwards their public
inputs verbatim (order-preserving, no shuffle), prepending an `aggregator_address`
that the chain uses to pay a fee rebate to whoever performed the aggregation.

## Changes

- **Terminology rename** across circuits, provers, Lean spec, and docs
  (`layer0`/`layer1` → `private_batch`/`public_batch`). `config.json` keeps backward
  compatibility via a serde alias (`num_layer0_proofs` → `num_private_batch_proofs`).
- **Non-ZK public-batch circuit config** (`wormhole_public_batch_circuit_config()`):
  the witnesses of a public batch are private-batch proofs whose public inputs are
  already public, so blinding buys nothing and slows the prover.
- **Dummy padding for partial batches**: circuit binary generation now emits
  `dummy_private_batch_proof.bin` (an all-dummy private batch with `block_hash == 0`).
  The public-batch circuit detects dummy inners, exempts them from asset/fee/block
  consistency checks, selects the reference header from the first non-dummy inner,
  and zeroes dummy exit slots and nullifiers in the output so no junk reaches chain
  state. `PublicBatchProver::commit` pads partial batches automatically.
- **Public-input parsing** (`qp-wormhole-inputs`, `qp-wormhole-verifier`):
  new `PublicBatchPublicInputs` struct and `parse_public_batch_public_inputs()`
  with layout constants parameterized by `(num_leaf_proofs, num_private_batch_proofs)`,
  used by the pallet to interpret public-batch proofs segment by segment.
- **Lean spec**: `RPublicBatch` updated to model dummy inners, header selection from
  the first non-dummy, and zeroing of forwarded dummy outputs.
- **Config validation**: proof counts bounded by `MAX_PROOF_COUNT`.

## Prover measurements

Measured on a dev laptop with N=7 leaves per private batch (14 outputs per segment),
one-time leaf + private-batch setup excluded:

| M | outputs | circuit build (s) | prover load (s) | prove (s) | proof size (KB) | prover.bin (MB) |
|---|---|---|---|---|---|---|
| 32 | 448 | 22.9 | 4.9 | 38.1 | 207 | 2,310 |
| 64 | 896 | 61.1 | 9.4 | 69.0 | 240 | 4,619 |
| 128 | 1,792 | 161.6 | 38.5 | OOM on this machine | — | 9,239 |

Prove time and artifact sizes scale roughly linearly in M. M=128 exceeds the memory
of the test machine; we expect follow-up PRs to improve these numbers. Default
branching factor remains 4.

## Notes for reviewers

- The forwarded nullifiers are deliberately **not** deduplicated in-circuit; the
  pallet performs segment-level denial (see the companion chain PR), so a public
  batch containing an already-spent segment still executes partially.
- `benches`/`memprof` references were updated mechanically as part of the rename.

## Test plan

- `cargo test` across the workspace (circuit logic tests include
  `public_batch_with_dummy_padding`).
- Lean spec builds; differential spec tests pass (`spec_differential.rs`).
- End-to-end verified against a dev chain via `quantus-cli wormhole multiround --public`
  (see companion CLI PR).
