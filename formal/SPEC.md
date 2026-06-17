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
| `WormholeSpec/Security.lean` | Deterministic cores of the reduction theorems (injective-RO model) |
| `WormholeSpec/Encoding.lean` | Byte↔felt encoding safety (4-byte injective edges, 8-byte canonical-only) |
| `WormholeSpec/LeafBinding.lean` | Finding A: chain↔circuit leaf-recipient consistency (spendable ⟺ recipient = `WA(s)`) |
| `../wormhole/tests/.../spec_differential.rs` | proptest harness: native oracles vs spec |
| `../wormhole/tests/.../encoding_safety.rs` | proptest harness: encoding round-trips + witnessed `{0,p}` collision |

## Building

```bash
cd formal
lake build
```

Phase 0 is intentionally **mathlib-free** so it builds in seconds and stays
hermetic. Toolchain is pinned in `lean-toolchain` (Lean `v4.30`).

## Modeling choices

- **Field.** `Felt` is `Nat` (`Basic.lean`). Finite-field facts that the spec
  needs (range checks, the 8-byte encoding's mod-`p` reduction) are modeled
  *explicitly* over `Nat` with the modulus `goldilocks` — see `Encoding.lean` —
  so they do not require `Felt` to be the field. **The representation is not a
  free global swap:** redefining `Felt := ZMod goldilocks` workspace-wide would
  make `Digest = Felt⁴` finite while `List Felt` stays infinite, so no injective
  `H` exists (pigeonhole), `RandomOracle` becomes uninhabited, and every
  RO-dependent theorem (`Security.lean`, `LeafBinding.lean`) silently turns
  *vacuous*. Today `Felt = Nat` is infinite, so `RandomOracle` is inhabited and
  those theorems have content. Phase-2 in-field arithmetic and Phase-4
  game-based resistance therefore live in a separate concrete-field layer; the
  RO modules stay over an infinite/abstract `Felt`. (See the warnings in
  `Basic.lean` / `Hash.lean`.)
- **Hash `H` as a random oracle.** Represented by an opaque total function `H`
  (capturing *determinism*) plus an `injective` field — the RO "no collisions"
  idealization that soundness/security proofs may invoke (`Hash.lean`). This
  *total* injectivity is consistent only over an infinite `Felt`; a compressing
  hash over a finite field is never literally injective, so the faithful
  finite-field model is the Phase-4 game (collisions negligibly rare, not
  impossible). The Phase-4 game-based track replaces this with an explicit lazily-sampled RO game;
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
| **thm** `rawOutputTotal_lt_modulus`: total `< goldilocks` | explicit no-wraparound bound from 32-bit output range checks; Phase-2 field hypothesis (see note below) |
| output layout (`Layer0Output`) | `aggregated_output` — `layer0/circuit/constants.rs` |
| `RL1` forwarding + consistency | `build_layer1_wrapper_constraints` — `layer1/circuit/circuit_logic.rs` |

### Security reductions (`Security.lean`)

Deterministic cores of the game-based theorems, in the injective-RO model.

| Spec clause | Paper | Notes |
|-------------|-------|-------|
| `WA_inj` (`WA s = WA s' → s = s'`) | §4.2 | collision resistance ⇒ injectivity, idealized |
| **thm** `same_deposit_same_nullifier` / `no_double_spend` | Thm (One-Time Withdrawal) | same deposit ⇒ same nullifier; `n₁ ≠ n₂` unsatisfiable |
| **thm** `spend_path_unique` (`H pk = WA s → pk = H(salt_wh ‖ s) .toList`) | Thm (Spend-Path Exclusivity) | unique outer preimage; case (2) ⟶ case (1) |

### Encoding safety (`Encoding.lean`)

The wormhole code mixes two byte→felt encodings (`qp-zk-circuits-common::serialization`,
thin wrappers over `qp-poseidon-core`). The spec models the per-limb field map
`feltOf v = v % p` — exactly `GoldilocksField::from_noncanonical_u64` on a `u64`
limb (`u64::from_le_bytes` being the std bijection bytes ↔ `[0,2^64)`).

| Spec clause | Encoding | Rust source |
|-------------|----------|-------------|
| `feltOf_id_of_lt_2pow32` (32-bit limbs never reduce) | 4 bytes/felt + `0x01` terminator | `bytes_to_felts` / `felts_to_bytes` — `common/src/serialization.rs:113–127` |
| `feltOf_inj_canonical` / `bytesToDigest_inj_canonical` (injective on canonical) | 8 bytes/felt | `bytes_to_digest` — `common/src/serialization.rs:173–179` |
| `feltOf_not_injective` / `feltOf_collision_iff` (`{w, w+p}` collisions) | 8 bytes/felt | `from_noncanonical_u64` reduction — same |

The argument: **edges** (attacker-controllable preimages) use the 4-byte
encoding, whose limbs are all `< 2^32 ≤ p`, so it is injective *unconditionally*;
**hash outputs** use the 8-byte encoding, which is injective *only* on canonical
limbs (`< p`). Genuine Poseidon2 outputs are canonical by construction, so the
8-byte path is safe **provided** no attacker-controllable, non-canonical byte
string ever reaches it. That proviso is a property of the *callers* (gap 7), not
of the encoding; `digest_decode_collides_off_canonical` in the Rust harness
exhibits the `{0, p}` collision that makes the precondition load-bearing.

### Leaf-recipient binding (`LeafBinding.lean`) — Finding A, formalized

In the circuit the recipient is witnessed as **felts** (the byte decode happens
only off-circuit when the pallet builds the tree), so Finding A is a chain↔circuit
*consistency* fact. Modeling `chainLeafHash` (pallet side, decodes recipient bytes)
against `RandomOracle.leafHash` (circuit side, hashes felts, with C2 pinning them
to `WA(s)`):

| Spec clause | Content |
|-------------|---------|
| `chain_circuit_leaf_eq_iff` | pallet leaf = circuit `WA(s)` leaf ⟺ recipient *decodes* to `WA(s)` (`H` injective) |
| `spendable_recipient_reduces_to_address` | **any** spendable recipient reduces to `WA(s)` — a non-canonical alias binds to the same address/nullifier, no advantage |
| `spendable_iff_is_wormhole_address` | among **canonical** recipients the spendable one is **unique** = `WA(s)` |
| `wormhole_address_canonical` | `WA(s)` is canonical (RO outputs are), so the honest recipient meets the precondition |
| `distinct_secrets_distinct_recipients` | distinct secrets ⟹ distinct unique recipients (via `WA_inj`) |

This converts Finding A's English argument into machine-checked facts: the
byte-level non-injectivity only ever maps to the canonical reduction `WA(s)`, so it
grants an attacker nothing. The computational "cannot produce `WA(s)` without `s`"
step is the Phase-4 preimage game, as for the other security theorems.

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
   **Field caveat:** conservation is an exact `Nat` identity; over `ZMod p`
   (Phase 2) it is only equality mod `p`, so the field statement must carry
   `rawOutputTotal leaves < goldilocks`. That bound is proved here
   (`rawOutputTotal_lt_modulus`) from the 32-bit output range checks plus a
   batch-size bound, and the `omega` proofs in `Aggregation.lean` will need
   field reworking. (See the conservation note in the module header.)
3. **L1 accounting.** `totalExitSlots` and aggregator-address binding semantics
   (Phase 3).
4. **Dummy-notion compatibility.** Prove the leaf dummy (`blockHash=0 ∧ outs=0`)
   and L0 dummy (`blockHash=0`) interact safely (Phase 3).
5. **`exit_account_1/2` are unconstrained at the leaf** — bound only at L0. The
   spec reflects this (no `Rleaf` clause references them); the binding obligation
   lives in `RL0`.
6. **Game-based probabilistic accounting.** `Security.lean` proves the
   *deterministic* cores of one-time withdrawal and spend-path exclusivity in the
   injective-RO model. The `ε_coll`/`ε_pre` terms and the knowledge-soundness
   extractor (and likewise deposit binding, nullifier indistinguishability, and
   transaction unlinkability) require an explicit lazily-sampled RO game — the
   Phase-4 track, out of scope for the current deterministic spec.
7. **Encoding call-site canonicality audit.** ~~Pending.~~ **Done (no exploitable
   bug).** `Encoding.lean` proves the 8-byte decode is injective *only* on
   canonical limbs (`< p`). Auditing every caller of `bytes_to_digest` /
   `bytes_to_felts_compact` across `qp-zk-circuits` and `chain`:

   - **Most sites feed canonical inputs:** node hashing (children are Poseidon
     outputs), `WA(s)` / nullifier digests, `parent_hash` / `zk_tree_root` /
     `block_hash` (Poseidon outputs), and `asset_id` / `amount` / `transfer_count`
     (range-checked `< 2^32`). The precondition holds directly.
   - **Two sites feed genuinely non-canonical bytes,** but the non-injectivity is
     neutralized downstream rather than by the encoding:
     - **(A) zk-tree leaf recipient** (`hash_leaf` `to`, `tree.rs`): `record_transfer`
       runs on *every* transfer, so `to` is arbitrary. Safe because the withdrawal
       circuit binds the leaf's `to_account` felts to `WA(secret)` — a canonical
       Poseidon output — and the numeric fields are range-checked, so the nullifier
       `Null(s, count)` is pinned. A colliding recipient cannot target a victim's
       `WA(s)` without a preimage break and confers no advantage. **Invariant
       (load-bearing, implicit):** withdrawal soundness requires `to_account = WA(s)`
       with `WA(s)` canonical; the leaf hash commits only to the *canonical
       reduction* of the recipient, never the recipient bytes. Guarded with a
       `debug_assert` + doc note in `hash_leaf`.
     - **(B) block-header `state_root` / `extrinsics_root`** (`primitives/header`,
       circuit `block_header`): substrate Blake2-256 → non-canonical. Irrelevant to
       wormhole soundness (only `zk_tree_root`, canonical and at a fixed offset,
       binds the proof). The substrate block hash is a *lossy* commitment to those
       two roots, but a collision needs real Blake2 roots differing by exactly `p`
       in a limb — not steerable. Comments corrected to stop calling Blake2 outputs
       "hash outputs" (the canonical-felt notion).

   **Conclusion:** the canonical-input precondition is satisfied for every
   security-critical binding; the two non-canonical sites are safe by downstream
   constraints, not by the encoding. Residual risk is *fragility* of the implicit
   invariant (A), now documented and `debug_assert`-guarded. Invariant (A) is also
   machine-checked in `LeafBinding.lean` (`spendable_iff_is_wormhole_address` and
   `spendable_recipient_reduces_to_address`).

## Intentionally-loose facts (must NOT be flagged as bugs)

- Leaf exit accounts are free public inputs (above).
- `asset_id` is constrained only via the Merkle leaf preimage, not a registry.
- The two dummy notions differ by layer (above).
- The `fake_leaf` test circuit does **not** implement C1–C5 and is not a
  verification target; only `WormholeCircuit` is.
