# Wormhole circuit — formal specification (Phase 0)

This directory holds the machine-checked **specification** of what the
`qp-zk-circuits` wormhole leaf and aggregation circuits are supposed to mean. It
is the reference that the Phase-2/3 soundness and completeness proofs check the
circuit against. Nothing here proves the circuit correct yet — Phase 0 is the
spec + the differential safety net.

## Layout

| File | Contents |
|------|----------|
| `WormholeSpec/Basic.lean` | Field/digest model, salts, `inRange` |
| `WormholeSpec/Hash.lean` | Random-oracle interface, `WA`/`Null`/`leafHash`/`nodeHash`/`dummyNull` |
| `WormholeSpec/Leaf.lean` | Leaf relation `Rleaf` (C1–C5, conditional dummy path) |
| `WormholeSpec/Aggregation.lean` | `RL0`, `RL1` |
| `../wormhole/tests/.../spec_differential.rs` | proptest harness: native oracles vs spec |

## Building

```bash
cd formal
lake build
```

Phase 0 is intentionally **mathlib-free** so it builds in seconds and stays
hermetic. Toolchain is pinned in `lean-toolchain` (Lean `v4.30`).

## Modeling choices

- **Field.** `Felt` is `Nat` as a placeholder (`Basic.lean`). The spec only needs
  hash I/O and range bounds, both faithful over `Nat`. **Phase 2** swaps in
  `abbrev Felt := ZMod 0xFFFFFFFF00000001` (mathlib) and the CVC5 finite-field
  tactic; no other module references the representation.
- **Hash `H` as a random oracle.** Represented by an opaque total function `H`
  (capturing *determinism*) plus an `injective` field — the RO "no collisions"
  idealization that soundness/security proofs may invoke (`Hash.lean`). The
  Phase-4 game-based track replaces this with an explicit lazily-sampled RO game;
  this structure is the seam.
- **TCB.** Not re-verified: Plonky2's FRI/PLONK soundness, the `PoseidonGate`
  implementation, the Lean kernel. The claim is: *given a sound proof system and
  a correct Poseidon2 gate, the constraints implement these relations.*

## Clause ↔ code cross-reference

### Leaf relation `Rleaf` (`Leaf.lean`)

| Spec clause | Paper | Rust source |
|-------------|-------|-------------|
| `WA s = H(H(salt_wh ‖ s))` (`RandomOracle.WA`) | C2 | `UnspendableAccount::from_secret` / `::circuit` — `wormhole/circuit/src/unspendable_account.rs` (salt `UNSPENDABLE_SALT = "wormhole"`) |
| `Null s c = H(H(salt_null ‖ s ‖ c))` (`RandomOracle.Null`) | C1 | `Nullifier::from_preimage` — `nullifier.rs` (salt `NULLIFIER_SALT = "~nullif~"`); in-circuit in `connect_shared_targets` — `circuit.rs:282–304` |
| `leafHash` preimage order `to_account ‖ tc ‖ asset_id ‖ input` | C3 | `ZkLeaf::collect_for_hash` — `zk_merkle_proof.rs:101–112,419–422` |
| `nodeHash` 4-ary `H(c0‖c1‖c2‖c3)` | C3 | `zk_merkle_proof.rs:518–524` |
| `computeRoot` / `stepUp` position insert | C3 | Merkle walk + position `select` — `zk_merkle_proof.rs:433–536` |
| `depth ≤ maxDepth`, `pos < 4` | C3 | `enforce_target_less_than_const`, `range_check(position, 2)` — `zk_merkle_proof.rs:425–426,441–442` |
| `feeOk` `(o₁+o₂)·10000 ≤ in·(10000−fee)` | C5 | `zk_merkle_proof.rs:409–417` |
| `inRange 32 …` (transfer_count ×2, asset_id, input, outputs, volume_fee_bps) | C5/C3 | `ZkLeaf::collect_32_bit_targets` + `range_check(_,32)` — `zk_merkle_proof.rs:114–125,404–407` |
| `inRange 32 block_number` | C4 | `range_check(_, 32)` — `block_header/mod.rs:71–73` |
| `headerPreimage` order | C4 | `HeaderTargets::collect_to_vec` — `block_header/header.rs:63–75` |
| root binding `zkTreeRoot = rootHash` | C4 | `connect_shared_targets` — `circuit.rs:331–338` |
| dummy gating `¬isDummy → {C1, C4, root}` | §4 | `is_not_dummy` multiply-by-flag — `circuit.rs:251–338`, `zk_merkle_proof.rs:538–543` |
| `isDummy = blockHash=0 ∧ outs=0` | §4 | `circuit.rs:251–276` |

### Aggregation (`Aggregation.lean`)

| Spec clause | Rust source |
|-------------|-------------|
| `metadataConsistent` (asset/fee/block across non-dummy) | `build_layer0_wrapper_constraints` — `layer0/circuit/circuit_logic.rs` |
| `referenceFromFirstReal` (block ref = first non-dummy slot) | prefix-scan selection — `layer0/circuit/circuit_logic.rs` (the `illuzen/full-shuffle` fix) |
| `nullifiersReplaced` `DNull(u)=H(H(u))` | `hash_dummy_nullifier_pre_image` — `circuit_logic.rs:338–346` |
| `isDummyL0 = blockHash=0` (weaker sentinel) | dummy detection at L0 — `circuit_logic.rs` |
| `groupExits` / `matchSum` (per-slot group sum + first-occurrence dedup) | exit-account grouping loop — `circuit_logic.rs:214–287` |
| **thm** `RL0_value_conservation`: `outputExitTotal = rawOutputTotal` | derived from the grouping primitive (was an assumed conjunct) |
| output layout (`Layer0Output`) | `aggregated_output` — `layer0/circuit/constants.rs` |
| `RL1` forwarding + consistency | `build_layer1_wrapper_constraints` — `layer1/circuit/circuit_logic.rs` |

## Known gaps / TODOs (tracked for later phases)

1. ~~Range-check set.~~ **Done.** Confirmed against `ZkLeaf::collect_32_bit_targets`:
   `transfer_count` (both limbs), `asset_id`, `input_amount`, `output_amount_1`,
   `output_amount_2`, `volume_fee_bps` (all unconditional 32-bit), plus
   `block_number` in `BlockHeader::circuit`. `Rleaf` now asserts the full set.
2. ~~Exit grouping/dedup.~~ **Done (conservation).** `RL0` now pins the exact
   in-circuit grouping (`groupExits`), and value conservation is the *derived*
   theorem `RL0_value_conservation` (with `rawOutputTotal_eq_inputExitTotal`
   bridging to the non-dummy total under the dummy⟹zero-outputs guarantee).
   Remaining: the full per-account *multiset* characterization (which account
   gets which sum) and `numExitSlots = 2·N` slot accounting (Phase 3).
3. **L1 accounting.** `totalExitSlots` and aggregator-address binding semantics
   (Phase 3).
4. **Dummy-notion compatibility.** Prove the leaf dummy (`blockHash=0 ∧ outs=0`)
   and L0 dummy (`blockHash=0`) interact safely (Phase 3).
5. **`exit_account_1/2` are unconstrained at the leaf** — bound only at L0. The
   spec reflects this (no `Rleaf` clause references them); the binding obligation
   lives in `RL0`.

## Intentionally-loose facts (must NOT be flagged as bugs)

- Leaf exit accounts are free public inputs (above).
- `asset_id` is constrained only via the Merkle leaf preimage, not a registry.
- The two dummy notions differ by layer (above).
- The `fake_leaf` test circuit does **not** implement C1–C5 and is not a
  verification target; only `WormholeCircuit` is.
