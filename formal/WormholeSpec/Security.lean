/-
  Deterministic cores of the whitepaper's reduction-style security theorems.

  The paper states these as game-based reductions to *computational* hardness:
  collision resistance (`one-time withdrawal`, §4.2) and preimage resistance
  (`spend-path exclusivity`, §4.3). We follow that shape literally: each result has

    * a **reduction** form (`*_or_collision`), provable for *any* `H` with no
      assumption — "if the scheme breaks, here is an explicit collision in `H`";
    * a **corollary** under the explicit `CollisionResistant ro` hypothesis, which
      eliminates the collision branch and recovers the clean structural conclusion:
        - collision resistance ⇒ derivations are injective, so "same deposit ⇒ same
          nullifier" (hence two distinct nullifiers cannot come from one deposit);
        - preimage resistance ⇒ the wormhole address has a *unique* outer preimage,
          the structured inner value `H(salt_wh ‖ s)` — the paper's case (2)
          collapses into case (1), there is exactly one spend path.

  Splitting the assumption out of `RandomOracle` (see `Hash.lean`) is what lets the
  oracle be instantiated by the concrete finite-field sponge: the reductions survive
  a compressing `H`, and collision resistance is invoked only at the corollary.

  The probabilistic accounting (the `ε_coll`/`ε_pre` terms and the
  knowledge-soundness extractor) is the Phase-4 game-based track, out of scope here.
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

/-! ### Reductions — hold for *any* `H`, no assumption.
    Each says: from a (would-be) break, *construct* a collision in `H`. -/

/-- The double hash `H(H(·))`: equal images give equal preimages, or a collision in
    `H` (at the inner or the outer call). -/
theorem hh_inj_or_collision {x y : List Felt} (h : ro.hh x = ro.hh y) :
    x = y ∨ HasCollision ro.H := by
  unfold RandomOracle.hh at h
  rcases ro.hash_inj_or_collision _ _ h with htl | hcol
  · exact ro.hash_inj_or_collision x y (Digest.toList_inj htl)
  · exact Or.inr hcol

/-- **One-time withdrawal, reduction form** (§4.2): if two distinct secrets share a
    wormhole address, that is a collision in `H`. -/
theorem WA_inj_or_collision {s s' : Digest} (h : ro.WA s = ro.WA s') :
    s = s' ∨ HasCollision ro.H := by
  unfold RandomOracle.WA at h
  rcases ro.hh_inj_or_collision h with h1 | hcol
  · exact Or.inl (Digest.toList_inj (List.append_cancel_left h1))
  · exact Or.inr hcol

/-- A deposit determines its nullifier — or the shared address is an `H` collision. -/
theorem same_deposit_same_nullifier_or_collision
    {s₁ s₂ : Digest} {c₁ c₂ : List Felt}
    (haddr : ro.WA s₁ = ro.WA s₂) (hc : c₁ = c₂) :
    ro.Null s₁ c₁ = ro.Null s₂ c₂ ∨ HasCollision ro.H := by
  rcases ro.WA_inj_or_collision haddr with hs | hcol
  · exact Or.inl (by rw [hs, hc])
  · exact Or.inr hcol

/-- **Spend-path exclusivity, reduction form** (§4.3): any `pk` with `H(pk) = WA(s)`
    is the structured inner value `H(salt_wh ‖ s)`, or `pk` collides with it under
    `H`. -/
theorem spend_path_unique_or_collision {pk : List Felt} {s : Digest}
    (h : ro.H pk = ro.WA s) :
    pk = (ro.H (wormholeSalt ++ s.toList)).toList ∨ HasCollision ro.H := by
  unfold RandomOracle.WA RandomOracle.hh at h
  exact ro.hash_inj_or_collision _ _ h

/-! ### Corollaries — under the explicit `CollisionResistant ro` assumption. -/

/-- The double hash `H(H(·))` inherits injectivity from a collision-resistant `H`. -/
theorem hh_inj (cr : ro.CollisionResistant) {x y : List Felt} (h : ro.hh x = ro.hh y) :
    x = y :=
  (ro.hh_inj_or_collision h).resolve_right cr.notHasCollision

/-- C2 derivation is injective: distinct secrets yield distinct wormhole addresses. -/
theorem WA_inj (cr : ro.CollisionResistant) {s s' : Digest} (h : ro.WA s = ro.WA s') :
    s = s' :=
  (ro.WA_inj_or_collision h).resolve_right cr.notHasCollision

/-- **One-time withdrawal core** (§4.2): a deposit determines its nullifier.
    Both proofs in the double-spend game reference the same deposit, so they share
    the wormhole address (`haddr`, collision resistance forces the same secret)
    and the same ZK-tree counter (`hc`, the counter is part of the authenticated
    leaf); hence the nullifiers coincide. The game's winning requirement
    `n₁ ≠ n₂` is therefore unsatisfiable. -/
theorem same_deposit_same_nullifier (cr : ro.CollisionResistant)
    {s₁ s₂ : Digest} {c₁ c₂ : List Felt}
    (haddr : ro.WA s₁ = ro.WA s₂) (hc : c₁ = c₂) :
    ro.Null s₁ c₁ = ro.Null s₂ c₂ :=
  (ro.same_deposit_same_nullifier_or_collision haddr hc).resolve_right cr.notHasCollision

/-- Contrapositive used in the double-spend reduction: two distinct nullifiers
    cannot have come from the same deposit. -/
theorem no_double_spend (cr : ro.CollisionResistant)
    {s₁ s₂ : Digest} {c₁ c₂ : List Felt}
    (haddr : ro.WA s₁ = ro.WA s₂) (hc : c₁ = c₂)
    (hn : ro.Null s₁ c₁ ≠ ro.Null s₂ c₂) : False :=
  hn (ro.same_deposit_same_nullifier cr haddr hc)

/-- **Spend-path exclusivity core** (§4.3): the *only* preimage of a wormhole
    address `WA(s)` under the outer hash is the structured inner value
    `H(salt_wh ‖ s)`. Any `pk` the adversary controls with `H(pk) = WA(s)` must
    equal it, so the paper's case (2) ("some other `pk`") collapses into case (1).
    Combined with `|pk| > |H|` for post-quantum keys (case (1) is then
    impossible), there is no spend path other than knowing `s`. -/
theorem spend_path_unique (cr : ro.CollisionResistant) {pk : List Felt} {s : Digest}
    (h : ro.H pk = ro.WA s) :
    pk = (ro.H (wormholeSalt ++ s.toList)).toList :=
  (ro.spend_path_unique_or_collision h).resolve_right cr.notHasCollision

end RandomOracle

/-! ### Payoff: the oracle is now inhabited by *non-injective* hashes.

    With the old `injective` field this section would not type-check — you cannot build
    a `RandomOracle` from a compressing hash. Now `RandomOracle` is just `H`, so it
    admits any hash, including the concrete finite-field Poseidon2 sponge
    (`Plonky2Spec.Sponge.H`, Step 3c), which a future adapter package can drop in as
    `{ H := … }`. The security theorems apply to *every* such oracle via the
    `*_or_collision` reductions; they need `CollisionResistant` only for the clean
    corollaries — which a compressing hash genuinely fails, as below. -/
namespace Demo

/-- A maximally-compressing oracle: every preimage maps to the zero digest. It inhabits
    `RandomOracle` despite being the opposite of injective. -/
def collapsingRO : RandomOracle := { H := fun _ => Digest.zero }

/-- It is honestly *not* collision-resistant — so the reductions above are non-vacuous:
    `[]` and `[0]` are a collision. -/
example : ¬ collapsingRO.CollisionResistant := fun cr =>
  absurd (cr [] [0] rfl) (by decide)

/-- And the reduction *constructs* a collision: two distinct secrets share the
    (degenerate) wormhole address, and `WA_inj_or_collision` returns the right disjunct. -/
example : HasCollision collapsingRO.H :=
  (collapsingRO.WA_inj_or_collision (s := Digest.zero) (s' := ⟨1, 0, 0, 0⟩) rfl).resolve_left
    (by decide)

end Demo

end WormholeSpec
