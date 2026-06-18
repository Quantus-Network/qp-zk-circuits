/-
  Deterministic cores of the whitepaper's reduction-style security theorems.

  The paper states these as game-based reductions to *computational* hardness:
  collision resistance (`one-time withdrawal`, §4.2) and preimage resistance
  (`spend-path exclusivity`, §4.3). In our spec we model `H` as an injective
  random oracle (`RandomOracle.injective`, see `Hash.lean`), which is the standard
  idealization. Under that idealization the computational reductions become
  *exact* structural facts:

    * collision resistance ⇒ derivations are injective, so "same deposit ⇒ same
      nullifier" (hence two distinct nullifiers cannot come from one deposit);
    * preimage resistance ⇒ the wormhole address has a *unique* outer preimage,
      the structured inner value `H(salt_wh ‖ s)` — i.e. the paper's case (2)
      collapses into case (1), there is exactly one spend path.

  These discharge the deterministic skeleton the game proofs hang on; the
  probabilistic accounting (the `ε_coll`/`ε_pre` terms and the knowledge-soundness
  extractor) is the Phase-4 game-based track and is out of scope here.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash

namespace WormholeSpec

/-- A digest is determined by its felt list: `toList` is injective. -/
theorem Digest.toList_inj {a b : Digest} (h : a.toList = b.toList) : a = b := by
  cases a; cases b
  simp only [Digest.toList] at h
  injection h with h0 h
  injection h with h1 h
  injection h with h2 h
  injection h with h3 _
  subst h0; subst h1; subst h2; subst h3; rfl

namespace RandomOracle

variable (ro : RandomOracle)

/-- The double hash `H(H(·))` inherits injectivity from `H`. -/
theorem hh_inj {x y : List Felt} (h : ro.hh x = ro.hh y) : x = y := by
  unfold RandomOracle.hh at h
  exact ro.injective _ _ (Digest.toList_inj (ro.injective _ _ h))

/-- C2 derivation is injective: distinct secrets yield distinct wormhole
    addresses. (Collision resistance, idealized.) -/
theorem WA_inj {s s' : Digest} (h : ro.WA s = ro.WA s') : s = s' := by
  unfold RandomOracle.WA at h
  have h1 : wormholeSalt ++ s.toList = wormholeSalt ++ s'.toList := ro.hh_inj h
  exact Digest.toList_inj (List.append_cancel_left h1)

/-- **One-time withdrawal core** (§4.2): a deposit determines its nullifier.
    Both proofs in the double-spend game reference the same deposit, so they share
    the wormhole address (`haddr`, collision resistance forces the same secret)
    and the same ZK-tree counter (`hc`, the counter is part of the authenticated
    leaf); hence the nullifiers coincide. The game's winning requirement
    `n₁ ≠ n₂` is therefore unsatisfiable. -/
theorem same_deposit_same_nullifier
    {s₁ s₂ : Digest} {c₁ c₂ : List Felt}
    (haddr : ro.WA s₁ = ro.WA s₂) (hc : c₁ = c₂) :
    ro.Null s₁ c₁ = ro.Null s₂ c₂ := by
  have hs : s₁ = s₂ := ro.WA_inj haddr
  rw [hs, hc]

/-- Contrapositive used in the double-spend reduction: two distinct nullifiers
    cannot have come from the same deposit. -/
theorem no_double_spend
    {s₁ s₂ : Digest} {c₁ c₂ : List Felt}
    (haddr : ro.WA s₁ = ro.WA s₂) (hc : c₁ = c₂)
    (hn : ro.Null s₁ c₁ ≠ ro.Null s₂ c₂) : False :=
  hn (ro.same_deposit_same_nullifier haddr hc)

/-- **Spend-path exclusivity core** (§4.3): the *only* preimage of a wormhole
    address `WA(s)` under the outer hash is the structured inner value
    `H(salt_wh ‖ s)`. Any `pk` the adversary controls with `H(pk) = WA(s)` must
    equal it, so the paper's case (2) ("some other `pk`") collapses into case (1).
    Combined with `|pk| > |H|` for post-quantum keys (case (1) is then
    impossible), there is no spend path other than knowing `s`. -/
theorem spend_path_unique {pk : List Felt} {s : Digest}
    (h : ro.H pk = ro.WA s) :
    pk = (ro.H (wormholeSalt ++ s.toList)).toList := by
  unfold RandomOracle.WA RandomOracle.hh at h
  exact ro.injective _ _ h

end RandomOracle

end WormholeSpec
