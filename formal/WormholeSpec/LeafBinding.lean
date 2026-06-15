/-
  Finding A (encoding call-site audit): the zk-tree leaf recipient binding.

  The on-chain pallet builds each tree leaf by decoding the recipient *account
  bytes* with the non-injective 8-byte/felt encoding (`hash_leaf` in
  `pallets/zk-tree/src/tree.rs`). The recipient is arbitrary (every transfer is
  recorded), so it need not be canonical — which is exactly the case
  `Encoding.lean` shows is unsafe *for the encoding in isolation*.

  This module discharges why it is nonetheless safe *for the wormhole circuit*.
  The crucial observation is that **in the circuit the recipient is witnessed as
  field elements, not bytes**: the byte decode happens only off-circuit when the
  pallet builds the tree. So Finding A is a chain↔circuit *consistency* fact.

  We model the two leaf-hash computations:
  * `chainLeafHash` — pallet side, decodes the recipient bytes (`bytesToDigest`);
  * `RandomOracle.leafHash` — circuit side, hashes the recipient felts directly,
    where the circuit's C2 constraint pins those felts to `WA(secret)`.

  Results:
  * `chain_circuit_leaf_eq_iff` — a chain leaf and the circuit's `WA(s)` leaf hash
    to the same value iff the recipient *decodes* to `WA(s)` (injective `H`);
  * `spendable_recipient_reduces_to_address` — therefore ANY spendable recipient
    (canonical or not) reduces to `WA(s)`: a non-canonical alias binds to the same
    address and nullifier, conferring no advantage;
  * `spendable_iff_is_wormhole_address` — among *canonical* recipients the
    spendable one is **unique**: exactly `WA(s)`. No different canonical recipient
    can be made spendable;
  * `wormhole_address_canonical` — `WA(s)` is canonical (RO outputs are), so the
    honest recipient meets the precondition above;
  * `distinct_secrets_distinct_recipients` — distinct secrets give distinct unique
    recipients (via `WA_inj`).

  Together: a leaf is spendable for `s` iff its recipient reduces to the canonical
  address `WA(s)`; the byte-level non-injectivity only ever maps to that same
  canonical reduction, so it grants an attacker nothing. The computational "cannot
  produce `WA(s)` without knowing `s`" step is the Phase-4 preimage-resistance
  game, as for the other security theorems.
-/
import WormholeSpec.Hash
import WormholeSpec.Encoding
import WormholeSpec.Security

namespace WormholeSpec

/-- The compact decode is the identity on a canonical limb list: this is the
    felt-level statement that a canonical recipient is recovered losslessly. -/
theorem bytesToDigest_canonical_id :
    ∀ {l : List Nat}, (∀ v ∈ l, Canonical v) → bytesToDigest l = l := by
  intro l
  induction l with
  | nil => intro _; rfl
  | cons x xs ih =>
      intro h
      simp only [bytesToDigest, List.map_cons]
      rw [feltOf_id_canonical (h x List.mem_cons_self)]
      have hxs : bytesToDigest xs = xs :=
        ih (fun v hv => h v (List.mem_cons_of_mem x hv))
      simp only [bytesToDigest] at hxs
      rw [hxs]

/-- A field digest's four felts are all canonical (`< p`). RO outputs are exactly
    such canonical digests; this packages "the hash returns canonical limbs".
    `abbrev` so `intro`/`exact` see through it to the underlying `∀`. -/
abbrev CanonicalDigest (d : Digest) : Prop := ∀ v ∈ d.toList, Canonical v

namespace RandomOracle

variable (ro : RandomOracle)

/-- The RO returns canonical digests (a Poseidon-over-Goldilocks hash always
    outputs limbs `< p`). The standard model takes this as part of the oracle. -/
def CanonicalOutputs : Prop := ∀ x, CanonicalDigest (ro.H x)

/-- The pallet-side leaf hash: the recipient *bytes* are decoded with the
    non-injective 8-byte/felt encoding before hashing. Mirrors `hash_leaf`. -/
def chainLeafHash (recipient transferCount : List Felt) (assetId inputAmount : Felt) : Digest :=
  ro.H (bytesToDigest recipient ++ transferCount ++ [assetId, inputAmount])

/-- `WA(s)` is canonical, so the honest recipient (the canonical wormhole address)
    satisfies the canonical-recipient precondition below. -/
theorem wormhole_address_canonical (hco : ro.CanonicalOutputs) (s : Digest) :
    CanonicalDigest (ro.WA s) := by
  intro v hv
  exact hco _ v hv

/-- Chain↔circuit consistency: a pallet leaf and the circuit's `WA(s)` leaf agree
    iff the recipient *decodes* to `WA(s)`. (`H` injective; cancel the common
    `transfer_count ‖ asset ‖ amount` suffix.) -/
theorem chain_circuit_leaf_eq_iff
    {recipient transferCount : List Felt} {assetId inputAmount : Felt} {s : Digest} :
    ro.chainLeafHash recipient transferCount assetId inputAmount
        = ro.leafHash (ro.WA s) transferCount assetId inputAmount
      ↔ bytesToDigest recipient = (ro.WA s).toList := by
  unfold chainLeafHash RandomOracle.leafHash
  constructor
  · intro h
    have h2 := ro.injective _ _ h
    exact List.append_cancel_right (List.append_cancel_right h2)
  · intro h
    rw [h]

/-- ANY spendable recipient reduces to `WA(s)`: a non-canonical alias binds to the
    same address (and hence the same nullifier `Null(s, c)`), so it gains nothing. -/
theorem spendable_recipient_reduces_to_address
    {recipient transferCount : List Felt} {assetId inputAmount : Felt} {s : Digest}
    (h : ro.chainLeafHash recipient transferCount assetId inputAmount
        = ro.leafHash (ro.WA s) transferCount assetId inputAmount) :
    bytesToDigest recipient = (ro.WA s).toList :=
  (ro.chain_circuit_leaf_eq_iff).1 h

/-- **Finding A core**: among *canonical* recipients, the recipient spendable for
    secret `s` is **unique** — it must be exactly the wormhole address `WA(s)`. No
    different canonical recipient can be crafted to be spendable. -/
theorem spendable_iff_is_wormhole_address
    {recipient transferCount : List Felt} {assetId inputAmount : Felt} {s : Digest}
    (hrec : ∀ v ∈ recipient, Canonical v) :
    ro.chainLeafHash recipient transferCount assetId inputAmount
        = ro.leafHash (ro.WA s) transferCount assetId inputAmount
      ↔ recipient = (ro.WA s).toList := by
  rw [ro.chain_circuit_leaf_eq_iff, bytesToDigest_canonical_id hrec]

/-- Distinct secrets yield distinct unique recipients: a leaf spendable for `s` is
    never spendable for `s' ≠ s`. (Ties Finding A to `WA_inj`.) -/
theorem distinct_secrets_distinct_recipients {s s' : Digest}
    (h : (ro.WA s).toList = (ro.WA s').toList) : s = s' :=
  ro.WA_inj (Digest.toList_inj h)

end RandomOracle

end WormholeSpec
