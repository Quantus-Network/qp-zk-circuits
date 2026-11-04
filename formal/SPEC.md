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
| `WormholeSpec/Leaf.lean` | 11-felt proof-of-burn leaf relation `Rleaf` (C1–C4, conditional dummy path, dummy burns zero) |
| `WormholeSpec/Aggregation.lean` | `RPrivateBatch` (prover-chosen exit slots, aggregate segment fee), `RPublicBatch` |
| `WormholeSpec/AggregationBridge.lean` | Public-input-level wrapper relations; composition with the children's relations |
| `WormholeSpec/Security.lean` | Deterministic cores of the reduction theorems (`*_or_collision` + collision-resistance corollaries) |
| `WormholeSpec/Encoding.lean` | Byte↔felt encoding safety (4-byte injective edges, 8-byte canonical-only) |
| `WormholeSpec/LeafBinding.lean` | Finding A: chain↔circuit leaf-recipient consistency (spendable ⟺ recipient = `WA(s)`) |
| `../wormhole/tests/.../spec_differential.rs` | proptest harness: native oracles vs spec |
| `../wormhole/tests/.../encoding_safety.rs` | proptest harness: encoding round-trips + witnessed `{0,p}` collision |
| `traces/private_batch_wrapper_n{2,4}.json` | Gadget-call trace of the real private-batch wrapper at `n = 2` and `4` (rows, copy constraints, constants, public inputs, and every `GadgetBuilder` call with the rows/copies it emitted), recorded by `TracingBuilder` in `common/src/formal_trace.rs`. Consumed by `qp-plonky2/constraint-exporter` to generate and prove the wrapper's Lean decode theorem and its composition into `RPrivateBatch` (qp-plonky2 `formal/PLAN.md` Steps 8c and 8e). The aggregator's unit tests fail if it is stale; regenerate with `UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-aggregator --lib private_batch_wrapper_n` |
| `traces/public_batch_wrapper_n{2,4}.json` | The same for the real public-batch wrapper at `n_inner = 2` and `4` over `2`-leaf private batches (`build_public_batch_constraints`, wrapper logic only, on virtual inner PI targets). Regenerate with `UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-aggregator --lib public_batch_wrapper_n` |
| `traces/leaf_circuit.json` | The same for the whole leaf circuit (`WormholeCircuit`: every constraint of `build_leaf_constraints` on the targets of `CircuitTargets::new`, no recursion) — the 11 public inputs and the private witness targets by name. Consumed by the exporter to generate the leaf decode theorem and its bridge to `Rleaf` (qp-plonky2 `formal/PLAN.md` Step 9). Regenerate with `UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-circuit --test formal_trace` |

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
  force the `Nat`-level arithmetic/encoding proofs (`Aggregation` aggregate-fee
  bounds, `Encoding` byte bounds, all `omega`) to be reworked for modular arithmetic. The
  *hash interface* no longer pins the carrier (see next bullet). (See the warnings
  in `Basic.lean` / `Hash.lean`.)
- **Hash `H` with explicit collision resistance.** Represented by an opaque total
  function `H` (capturing *determinism*); `RandomOracle` carries **no** idealizing
  field, so it is inhabited by *any* `H` — including a compressing finite-field hash
  (`Hash.lean`). Collision resistance is a *separate, opt-in* predicate
  `RandomOracle.CollisionResistant`. The security results come in two forms: a
  **reduction** (`*_or_collision`) provable for any `H` with no assumption ("a scheme
  break constructs a collision in `H`"), and a **corollary** under
  `CollisionResistant` that recovers the clean conclusion. This is what lets the
  oracle be instantiated by the concrete finite-field Poseidon2 sponge
  (`Plonky2Spec.Sponge`); the old `injective` field made `RandomOracle` *uninhabited*
  over a finite field (pigeonhole) and every RO theorem vacuous. The `ε_coll`/`ε_pre`
  probabilistic accounting is the Phase-4 game-based track; this interface is the seam.
- **TCB and phase boundary.** Not re-verified: Plonky2's FRI/PLONK soundness, the
  `PoseidonGate` implementation, the Lean kernel, or the field-level wrapper
  gadgets. This package is axiom-free; proof-system soundness is the one explicit
  axiom `Plonky2Bridge.proof_sound` in qp-plonky2/formal (stated on the exported
  recursion tree), and the field-level bridges there (`Plonky2Bridge.*_end_to_end`)
  are what prove the field constraints implement the aggregate sums/comparison.

## Clause ↔ code cross-reference

### Leaf relation `Rleaf` (`Leaf.lean`)

| Spec clause | Paper | Rust source |
|-------------|-------|-------------|
| `WA s = H(H(salt_wh ‖ s))` (`RandomOracle.WA`) | C2 | `UnspendableAccount::from_secret` / `::circuit` — `wormhole/circuit/src/unspendable_account.rs` (salt `UNSPENDABLE_SALT = "wormhole"`) |
| `Null s c = H(H(salt_null ‖ s ‖ c))` (`RandomOracle.Null`) | C1 | `Nullifier::from_preimage` — `nullifier.rs` (salt `NULLIFIER_SALT = "~nullif~"`); in-circuit in `connect_shared_targets` — `circuit.rs:282–304` |
| `LeafPublic.inputAmount` is the final intermediate PI | aggregate-fee interface | leaf PI registration / parser (`INPUT_AMOUNT_INDEX = 10`); consumed only by private batch, not forwarded |
| `leafHash` preimage order `to_account ‖ tc ‖ asset_id ‖ input` | C3 | `ZkLeaf::collect_for_hash` — `zk_merkle_proof.rs:101–112,419–422` |
| `nodeHash` 4-ary `H(c0‖c1‖c2‖c3)` | C3 | `zk_merkle_proof.rs:518–524` |
| `computeRoot` / `stepUp` position insert | C3 | Merkle walk + position `select` — `zk_merkle_proof.rs:433–536` |
| `depth ≤ maxDepth`, `pos < 4` | C3 | `enforce_target_less_than_const`, `range_check(position, 2)` — `zk_merkle_proof.rs:425–426,441–442` |
| `inRange 32 …` (transfer_count ×2, asset_id, input) | C3/interface | `ZkLeaf::collect_32_bit_targets` + `range_check(_,32)` |
| `inRange 32 block_number` | C4 | `range_check(_, 32)` — `block_header/mod.rs:71–73` |
| `headerPreimage` order | C4 | `HeaderTargets::collect_to_vec` — `block_header/header.rs:63–75` |
| root binding `zkTreeRoot = rootHash` | C4 | `connect_shared_targets` — `circuit.rs:331–338` |
| dummy gating `¬isDummy → {C1, C4, root}` | §4 | `is_not_dummy` multiply-by-flag — `circuit.rs`, `zk_merkle_proof.rs` |
| `isDummy = blockHash=0` | §4 | `is_dummy = block_hash == 0` — `circuit.rs` |
| `isDummy → inputAmount = 0` | §4 | `is_dummy * input_amount == 0` — `circuit.rs` |

The leaf is a proof of burn: it carries no outputs and no fee, so the relation
has no fee inequality and no `volumeFeeBps` clause at all. It range-checks and
Merkle-binds `inputAmount`; exposing that amount in the intermediate leaf proof
lets the private wrapper enforce one aggregate inequality over its prover-chosen
exit slots without exposing or forwarding the segment input total.

### Aggregation (`Aggregation.lean`)

| Spec clause | Rust source |
|-------------|-------------|
| `metadataConsistent` (asset/block hash across non-dummy; block *number* is forwarded from the first real slot, not checked per slot) | `build_private_batch_constraints` — `private_batch/circuit/circuit_logic.rs` |
| `referenceFromFirstReal` (block ref = first non-dummy slot; all-dummy keeps the scan's zero hash/number) | prefix-scan selection — `private_batch/circuit/circuit_logic.rs` (the `illuzen/full-shuffle` fix) |
| `nullifiersReplaced` `DNull(u)=H(H(u))`, emitted in slot order | `hash_dummy_nullifier_pre_image` + per-slot `select` — `circuit_logic.rs` |
| `isDummyPrivateBatch = blockHash=0` (same sentinel as the leaf) | dummy detection at private-batch — `circuit_logic.rs` |
| `maskedInputTotal` | dummy-mask real leaf inputs before summing |
| `∀ s ∈ out.exitSlots, inRange 32 s.amount` | `range_check(slot.amount, 32)` over the witnessed exit slots — `circuit_logic.rs` |
| `privateBatchFeeOk`: `fee_bps ≤ 10000` and `outputExitTotal·10000 ≤ sum_in·(10000−fee_bps)` | one aggregate check per private segment over the prover-chosen exits; no totals are forwarded |
| `realNullifiersDistinct` (pairwise-distinct real nullifiers, anti-replay) | `and(and(is_real_i, is_real_j), digest_eq(null_i, null_j)) = 0` loop over `i < j` — `circuit_logic.rs` ("Real-nullifier uniqueness") |
| `numExitSlots = out.exitSlots.length` | `num_exit_slots_t = constant(num_exit_slots)` — `circuit_logic.rs` |
| **thm** `RPrivateBatch_settles_distinct_spends`: `outputExitTotal ≤ rawInputTotal (realLeaves)` ∧ `(realNullifiers).Nodup` | the property the uniqueness constraint protects: settled value is backed by distinct spends |
| **thm** `RPrivateBatch_real_nullifier_mem`, `RPrivateBatch_exitSlots_length` | every real nullifier reaches the output; the exit region has exactly `numExitSlots` slots |
| **thm** `RPrivateBatch_fee_conservation`, `RPrivateBatch_settlement_le_input` | the aggregate fee inequality and its unscaled corollary bound the settled output |
| **thm** `maskedInputTotal_mul_feeDenominator_lt_modulus`, `slotsTotal_mul_feeDenominator_lt_modulus`, `privateBatchFeeRhs_lt_modulus` | scaled fee operands cannot wrap for ≤64 leaves / ≤64 slots with 32-bit amounts |
| **thm** `privateBatchFeeRhs_lt_two_pow_52`, `privateBatchFeeLhs_add_two_pow_52_lt_modulus` | the two side conditions that make `range_check(rhs − lhs, 52)` sound: honest `rhs < 2^52`; wrapped `p − lhs > 2^52` |
| **thm** `sentinels_agree` / `rawInputTotal_eq_maskedInputTotal_of_Rleaf` | leaf and private-batch dummy sentinels are the same predicate; on valid leaves a dummy burns nothing, so the wrapper's input mask is defense in depth |
| output layout (`PrivateBatchOutput`) | `aggregated_output` — `private_batch/circuit/constants.rs` |
| `RPublicBatch` forwarding + consistency | `build_public_batch_constraints` — `public_batch/circuit/circuit_logic.rs` |
| `totalExitSlots = out.exitSlots.length`; **thm** `RPublicBatch_totalExitSlots` (= sum of inner slot counts) | `constant(n_inner * slots_per_inner)` — `public_batch/circuit/circuit_logic.rs` |

### Security reductions (`Security.lean`)

Deterministic cores of the game-based theorems. Each has a **reduction** form
(`*_or_collision`, no assumption, "break ⇒ explicit `H` collision") and a
**corollary** under the explicit `CollisionResistant ro` hypothesis.

| Spec clause | Paper | Notes |
|-------------|-------|-------|
| `WA_inj_or_collision` / `WA_inj` (`WA s = WA s' → s = s'`) | §4.2 | distinct secrets sharing an address ⇒ collision; injective under CR |
| **thm** `same_deposit_same_nullifier` / `no_double_spend` | Thm (One-Time Withdrawal) | same deposit ⇒ same nullifier; `n₁ ≠ n₂` unsatisfiable (under CR) |
| **thm** `spend_path_unique_or_collision` / `spend_path_unique` (`H pk = WA s → pk = H(salt_wh ‖ s) .toList`) | Thm (Spend-Path Exclusivity) | unique outer preimage (under CR); case (2) ⟶ case (1) |
| `Demo.collapsingRO` | — | payoff: a non-injective `H` inhabiting `RandomOracle` (impossible under the old `injective` field) |

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
| `chain_circuit_leaf_eq_iff` | pallet leaf = circuit `WA(s)` leaf ⟺ recipient *decodes* to `WA(s)` (under `CollisionResistant ro`) |
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
   `transfer_count` (both limbs), `asset_id`, `input_amount` (all unconditional
   32-bit), plus `block_number` in `BlockHeader::circuit_without_hash_binding`.
   The leaf is a proof of burn, so `LeafPublic` has no output, exit-account or
   fee fields; `Rleaf` additionally pins `isDummy → inputAmount = 0`.
2. ~~Aggregate fee relation.~~ **Done at the Phase-0 relation level.** Exit slots
   are prover-chosen witnesses of the private batch (`out.exitSlots`, each amount
   32-bit range-checked), and `RPrivateBatch` includes `privateBatchFeeOk` over
   `maskedInputTotal` and `outputExitTotal`. Thus value can pool across real
   leaves and split across exits, and each private segment satisfies exactly one
   `sum_out·10000 ≤ sum_in·(10000−fee_bps)` check with `fee_bps ≤ 10000`. The
   economically useful consequences are `RPrivateBatch_fee_conservation` and
   `RPrivateBatch_settlement_le_input`. There is no in-circuit exit grouping any
   more (slots are forwarded verbatim; a prover that wants merged outputs merges
   them before proving), so no per-account multiset characterization is owed.
   `numExitSlots = out.exitSlots.length` is a clause of `RPrivateBatch`.
   **Field caveat:** aggregate fee arithmetic is stated over `Nat`; over
   `ZMod p`, both scaled operands and the checked difference must not wrap.
   `maskedInputTotal_mul_feeDenominator_lt_modulus`,
   `slotsTotal_mul_feeDenominator_lt_modulus`, and
   `privateBatchFeeRhs_lt_modulus` prove the operand bounds for the protocol cap
   of 64 leaves / 64 slots and 32-bit amounts; `privateBatchFeeRhs_lt_two_pow_52` and
   `privateBatchFeeLhs_add_two_pow_52_lt_modulus` are the two-sided bounds the
   in-circuit `range_check(rhs − lhs, 52)` actually rests on. The field-level
   lift of those bounds through the range-check gadget lives in
   `qp-plonky2/formal` (`Plonky2Spec.Wrapper`).
3. ~~**public-batch accounting.**~~ **Done.** `totalExitSlots = out.exitSlots.length`
   is a clause of `RPublicBatch`; `RPublicBatch_totalExitSlots` equates it to the
   sum of inner slot counts. The aggregator address is a free witness bound by the
   `= addr` conjunct; its fee-recipient semantics are pallet-side, not a circuit
   constraint.
4. ~~**Dummy-notion compatibility.**~~ **Done (definitionally).** Both layers use
   `blockHash = 0` as the dummy sentinel (`sentinels_agree` is `Iff.rfl`), and
   `Rleaf` forces a dummy's `inputAmount` to zero, so the wrapper's input mask is
   defense in depth (`rawInputTotal_eq_maskedInputTotal_of_Rleaf`).
8. **Real-nullifier uniqueness.** ~~Not modeled.~~ **Done.** `realNullifiersDistinct`
   is a clause of `RPrivateBatch` (and `PrivateBatchCircuit`), mirroring the
   circuit's pairwise `i < j` loop. `RPrivateBatch_settles_distinct_spends` is the
   theorem the constraint exists for: the settled total is covered by the burns of
   the real children, whose nullifiers are `Nodup`. Not enforced (and not claimed): a
   *dummy* nullifier `DNull(u)` colliding with a real one — dummies never settle, so
   the circuit exempts them.
5. ~~**`exit_account_1/2` are unconstrained at the leaf.**~~ **Moot.** The leaf no
   longer carries exit accounts; exit slots are private-batch witnesses bound only
   by `privateBatchFeeOk`, and the leaf layout gives a poisoned dummy template no
   exit field to smuggle.
6. **Game-based probabilistic accounting.** `Security.lean` proves the
   *deterministic* cores of one-time withdrawal and spend-path exclusivity as
   reductions to an `H` collision, clean under the `CollisionResistant` hypothesis.
   The `ε_coll`/`ε_pre` terms and the knowledge-soundness
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
       reduction* of the recipient, never the recipient bytes. The corresponding
       chain-side guard (a `debug_assert` + doc note in `hash_leaf`) lives in the
       chain/pallet repo and is tracked there separately — it is *not* part of this
       PR (which touches only `formal/`, `Cargo.lock`, and `wormhole/tests/`). What
       this PR contributes is the argument and its machine-checking in
       `LeafBinding.lean`.
     - **(B) block-header `state_root` / `extrinsics_root`** (`primitives/header`,
       circuit `block_header`): substrate Blake2-256 → non-canonical. Irrelevant to
       wormhole soundness (only `zk_tree_root`, canonical and at a fixed offset,
       binds the proof). The substrate block hash is a *lossy* commitment to those
       two roots, but a collision needs real Blake2 roots differing by exactly `p`
       in a limb — not steerable. The misleading "hash outputs" comments on those
       Blake2 fields are corrected in the chain repo (tracked separately, not in
       this PR).

   **Conclusion:** the canonical-input precondition is satisfied for every
   security-critical binding; the two non-canonical sites are safe by downstream
   constraints, not by the encoding. Residual risk is *fragility* of the implicit
   invariant (A). The chain-side documentation/guard for (A) and (B) is tracked in
   the chain/pallet repo (separate PRs); within *this* PR, invariant (A) is
   machine-checked in `LeafBinding.lean` (`spendable_iff_is_wormhole_address` and
   `spendable_recipient_reduces_to_address`).

## Intentionally-loose facts (must NOT be flagged as bugs)

- Exit slots are free witnesses of the private batch (bound only by the 32-bit
  range checks and `privateBatchFeeOk`); several slots may name the same account
  and the circuit does not merge them.
- Leaf `inputAmount` is an intermediate public input for recursive aggregation,
  but private/public aggregate proofs do not forward it or either aggregate
  total.
- `asset_id` is constrained only via the Merkle leaf preimage, not a registry.
- The `fake_leaf` test circuit does **not** implement the canonical `Rleaf`
  constraints and is not a
  verification target; only `WormholeCircuit` is.
