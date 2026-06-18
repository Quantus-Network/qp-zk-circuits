/-
  Random-oracle interface and the hash derivations used by the circuit.

  H AS A RANDOM ORACLE
  --------------------
  At the specification level we represent the Poseidon2 hash as a *random oracle*
  via two pieces:

  1. `H : List Felt → Digest`, a total opaque function. Totality + functionhood
     already capture *determinism* (equal preimages give equal digests), which is
     all the functional spec needs.

  2. `injective`, the RO idealization that "no collisions occur". In a
     deterministic proof assistant collision resistance cannot be a theorem about
     a concrete function, so we surface it as an assumption that soundness proofs
     may invoke. Modeling the RO as injective is the standard spec-level
     idealization and is exactly what the deposit-binding / nullifier arguments
     rely on.

  WARNING — total injectivity is only consistent over an INFINITE `Felt`.
  ---------------------------------------------------------------------
  `HashInjective` quantifies over all of `List Felt` (infinite) into `Digest`
  (`Felt⁴`). With the current `Felt := Nat` the codomain is infinite, an injective
  `H` exists, and `RandomOracle` is inhabited — so the theorems downstream
  (`WA_inj`, `same_deposit_same_nullifier`, `spend_path_unique`, the Finding-A
  binding lemmas) are non-vacuous. But a *compressing* hash over a finite field is
  never literally injective: if `Felt` is swapped to `ZMod goldilocks`, `Digest`
  becomes finite, no injective `H : List Felt → Digest` exists (pigeonhole), and
  `RandomOracle` becomes uninhabited. Every theorem taking `ro : RandomOracle`
  would then be *vacuously* true and content-free. So this module must stay over
  an infinite / abstract `Felt`; never instantiate it at the concrete field.

  The faithful finite-field model is the Phase-4 game-based track (deposit
  binding, unlinkability, nullifier indistinguishability): an explicit
  lazily-sampled RO game with `ε_coll` / `ε_pre` advantage bounds, where
  collisions are *negligibly rare* rather than *impossible*. This interface is the
  seam where that richer model plugs in.
-/
import WormholeSpec.Basic

namespace WormholeSpec

/-- Build-time tripwire for the warning above. The RO idealization
    (`HashInjective`) is consistent only over an *infinite* carrier; this `rfl`
    pins `Felt` to `Nat`. If a future change redefines `Felt` as a finite field,
    THIS line stops compiling — forcing the author to confront the vacuity issue
    (move the RO modules to an abstract/infinite carrier, or the Phase-4 game)
    rather than silently turning every RO-dependent theorem vacuous. -/
example : Felt = Nat := rfl

/-- Spec-level injectivity for the hash (the RO "no collisions" idealization).
    Consistent ONLY over an infinite `Felt` (see the module-header warning): with
    a finite field this is unsatisfiable and makes `RandomOracle` uninhabited. -/
def HashInjective (H : List Felt → Digest) : Prop :=
  ∀ x y, H x = H y → x = y

/-- A Poseidon2 hash modeled as a random oracle. -/
structure RandomOracle where
  /-- The hash function: `hash_n_to_hash_no_pad` over Goldilocks, 4-felt output. -/
  H : List Felt → Digest
  /-- RO idealization: collisions do not occur (see module header). -/
  injective : HashInjective H

namespace RandomOracle

variable (ro : RandomOracle)

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
