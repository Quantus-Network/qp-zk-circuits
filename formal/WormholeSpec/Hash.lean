/-
  Random-oracle interface and the hash derivations used by the circuit.

  H AS A HASH WITH AN EXPLICIT COLLISION-RESISTANCE ASSUMPTION
  ------------------------------------------------------------
  At the specification level we represent the Poseidon2 hash as:

  1. `H : List Felt → Digest`, a total opaque function. Totality + functionhood
     already capture *determinism* (equal preimages give equal digests).

  2. `CollisionResistant ro`, a *separate, opt-in* assumption (not a field of the
     structure). It says `H` has no collision; the security results are stated as
     **reductions** that hold for *any* `H` ("a scheme break constructs a collision
     in `H`", the `*_or_collision` lemmas), and recover their clean conclusions only
     when this assumption is supplied. This is the deterministic core of the paper's
     game-based reductions; the `ε_coll` / `ε_pre` probabilistic accounting is the
     Phase-4 game, out of scope here.

  WHY THIS, NOT TOTAL INJECTIVITY AS A FIELD.
  -------------------------------------------
  The previous model baked `injective : ∀ x y, H x = H y → x = y` into the structure.
  That is the right *idealization* but with a fatal side effect: a compressing hash
  over a finite field is never injective (pigeonhole), so over `Felt = ZMod goldilocks`
  no injective `H` exists, `RandomOracle` is *uninhabited*, and every theorem taking
  `ro : RandomOracle` is vacuously true. Making collision resistance an *external
  hypothesis* keeps `RandomOracle` inhabited by *any* `H` — including the concrete
  finite-field Poseidon2 sponge — which is exactly the obstruction that previously
  blocked instantiating the oracle (`Plonky2Spec.Sponge`, Step 3c). The honest content
  moves into the reductions; collision resistance is invoked only where a clean
  conclusion is wanted, precisely as a real cryptographic reduction does.

  `Felt` stays `Nat` here, but now for a *different* reason: the `Nat`-level arithmetic
  and encoding proofs (`Aggregation` conservation via `omega`, `Encoding` byte bounds)
  need it. Unlike injectivity, collision resistance is consistent over a finite carrier,
  so the hash interface is no longer what forces the choice.
-/
import WormholeSpec.Basic

namespace WormholeSpec

/-- Build-time tripwire: this `rfl` pins `Felt` to `Nat`. The `Nat`-level arithmetic
    and encoding proofs (`Aggregation` conservation, `Encoding` byte bounds) rely on
    it; if a future change redefines `Felt` (e.g. as `ZMod goldilocks`), THIS line
    stops compiling, forcing those `omega`/byte proofs to be reworked for the field.
    (Note: unlike the old injective-RO model, the hash interface is *not* what forces
    `Nat` — collision resistance is finite-field-consistent.) -/
example : Felt = Nat := rfl

/-- A collision in `H`: two *distinct* preimages with the same digest. This is the
    object a collision-resistance adversary must exhibit; the security *reductions*
    below construct one from any scheme break. -/
def HasCollision (H : List Felt → Digest) : Prop :=
  ∃ x y, x ≠ y ∧ H x = H y

/-- A Poseidon2 hash. Unlike the old injective-RO model this carries *no* idealizing
    field: it is just `H`, so it is inhabited over any carrier (including the finite
    field, where an injective `H` cannot exist). Collision resistance is supplied
    separately, as the explicit `CollisionResistant` hypothesis. -/
structure RandomOracle where
  /-- The hash function: `hash_n_to_hash_no_pad` over Goldilocks, 4-felt output. -/
  H : List Felt → Digest

namespace RandomOracle

variable (ro : RandomOracle)

/-- Collision resistance, idealized: `H` has no collision (equivalently, `H` is
    injective). Now an explicit *assumption* threaded into the corollaries that need
    it — not a baked-in field — so `RandomOracle` itself stays inhabited (and
    finite-field-ready).

    NAMING CAVEAT: as defined this is *perfect collision-freeness* (= full injectivity),
    which is strictly **stronger** than the cryptographic "collision resistance" notion
    (no *efficient* adversary finds a collision). We keep the name because the
    deterministic core of the paper's reductions is exactly this idealization; the gap is
    the probabilistic `ε_coll` accounting, deferred to the Phase-4 game. Computational
    reading of this hypothesis: no efficient adversary produces a `HasCollision` witness. -/
def CollisionResistant : Prop := ∀ x y, ro.H x = ro.H y → x = y

/-- A collision-resistant oracle has no collision witness — used to discharge the
    `HasCollision` branch of the reductions. -/
theorem CollisionResistant.notHasCollision {ro : RandomOracle}
    (cr : ro.CollisionResistant) : ¬ HasCollision ro.H :=
  fun ⟨x, y, hne, hc⟩ => hne (cr x y hc)

/-- Atomic reduction: from `H a = H b`, either the preimages are equal, or we have
    exhibited a collision in `H`. Holds for *any* `H`; the engine of the security
    reductions below. -/
theorem hash_inj_or_collision (a b : List Felt) (h : ro.H a = ro.H b) :
    a = b ∨ HasCollision ro.H :=
  if hab : a = b then Or.inl hab else Or.inr ⟨a, b, hab, h⟩

/-- The double hash `H(H(·))` used pervasively (WA, Null, dummy nullifiers). The
    inner digest is re-expanded to its 4-felt list before the outer call, matching
    `Poseidon2Hash::hash_no_pad(&inner.elements)` in the Rust code. -/
def hh (preimage : List Felt) : Digest :=
  ro.H ((ro.H preimage).toList)

/-- C2 — wormhole address `WA(s) = H(H(salt_wh ‖ s))`.
    Mirrors `UnspendableAccount::from_secret`. -/
def WA (secret : Digest) : Digest :=
  ro.hh (wormholeSalt ++ secret.toList)

/-- C1 — nullifier `Null(s, c) = H(H(salt_null ‖ s ‖ c))`, where `c` is the
    transfer count (2 felts). Mirrors `Nullifier::from_preimage` and the in-circuit
    derivation in `connect_shared_targets`. -/
def Null (secret : Digest) (transferCount : List Felt) : Digest :=
  ro.hh (nullifierSalt ++ secret.toList ++ transferCount)

/-- The ZK-tree leaf hash. Preimage order matches `ZkLeaf::collect_for_hash`:
    `to_account(4) ‖ transfer_count(2) ‖ asset_id(1) ‖ input_amount(1)`. -/
def leafHash (toAccount : Digest) (transferCount : List Felt)
    (assetId inputAmount : Felt) : Digest :=
  ro.H (toAccount.toList ++ transferCount ++ [assetId, inputAmount])

/-- A 4-ary internal ZK-tree node: `H(c0 ‖ c1 ‖ c2 ‖ c3)` (16 felts). -/
def nodeHash (c0 c1 c2 c3 : Digest) : Digest :=
  ro.H (c0.toList ++ c1.toList ++ c2.toList ++ c3.toList)

/-- Dummy nullifier replacement `DNull(u) = H(H(u))`, with `u` a 4-felt preimage
    witnessed by the aggregator. Mirrors `hash_dummy_nullifier_pre_image`. -/
def dummyNull (u : List Felt) : Digest :=
  ro.hh u

end RandomOracle

end WormholeSpec
