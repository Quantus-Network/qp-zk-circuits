/-
  The aggregation bridge: the L0/L1 wrapper *circuit constraints* imply the spec
  relations `RL0` / `RL1`, and — composed with the trusted recursive-verifier
  soundness (`Trusted.lean`) — a satisfied aggregation circuit attests both its own
  relation and every child's relation.

  WHAT THIS MODELS. We model the wrapper constraints of `build_layer0_wrapper_constraints`
  / `build_layer1_wrapper_constraints` as the facts the circuit *enforces* on the
  decoded public inputs (`Layer0Circuit` / `Layer1Circuit`), then prove each implies
  the corresponding spec relation. The faithfulness of "the wrapper *gadgets* compute
  these conditionals" — `select`/`and`/`or`/the first-real prefix scan — is the
  separate, field-level (`ZMod p`) contribution of `qp-plonky2/formal`'s
  `Plonky2Spec.Wrapper`; the two compose at the `ZMod.val ↔ Felt` boundary (the
  cross-package seam, kept explicit since `WormholeSpec` is deliberately mathlib-free
  over `Felt = ℕ` and does not import the plonky2 spec). Concretely:

    * nullifier per slot      `select(is_dummy, H(H u), real)`  — `Plonky2Spec.Wrapper.nullifier_replacement`
    * exit grouping/dedup     `select`/`matchSum`/`groupAux`     — `Plonky2Spec.Wrapper.{match_contribution, dedup_select}`
    * block reference         first-real prefix scan             — `Plonky2Spec.Wrapper.scanFirst_correct`
    * metadata `or`-clause    `or(is_dummy, matches) = 1`        — `Plonky2Spec.Wrapper.{block_consistency, real_block_matches}`

  This file is the public-input-level half: given those conditionals, the constructed
  aggregate output satisfies `RL0` / `RL1`.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf
import WormholeSpec.Aggregation
import WormholeSpec.Trusted

namespace WormholeSpec

/-! ### Layer-0 -/

/-- The per-slot nullifier output the circuit builds: `select(is_dummy, H(H u), real)`
    for each `(child, preimage)` pair. Mirrors `nullifiersReplaced`'s per-slot body. -/
def buildNullifiers (ro : RandomOracle) :
    List LeafPublic → List (List Felt) → List Digest
  | [], _ => []
  | _, [] => []
  | p :: ps, u :: us =>
      (if isDummyL0 p then ro.dummyNull u else p.nullifier) :: buildNullifiers ro ps us

/-- `buildNullifiers` realizes `nullifiersReplaced` when there is one preimage per
    child (the circuit witness layout: `dummy_nullifier_pre_images.len() = n_leaf`). -/
theorem nullifiersReplaced_build (ro : RandomOracle) :
    ∀ (leaves : List LeafPublic) (us : List (List Felt)),
      us.length = leaves.length →
      nullifiersReplaced ro leaves us (buildNullifiers ro leaves us)
  | [], [], _ => trivial
  | p :: ps, u :: us, h => by
      refine ⟨rfl, nullifiersReplaced_build ro ps us ?_⟩
      simpa using h
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h

/-- `buildNullifiers` has one entry per child (matching `out.nullifiers.length`). -/
theorem buildNullifiers_length (ro : RandomOracle) :
    ∀ (leaves : List LeafPublic) (us : List (List Felt)),
      us.length = leaves.length →
      (buildNullifiers ro leaves us).length = leaves.length
  | [], [], _ => rfl
  | p :: ps, u :: us, h => by
      simp only [buildNullifiers, List.length_cons]
      rw [buildNullifiers_length ro ps us (by simpa using h)]
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h

/-- The layer-0 wrapper constraints, as the circuit enforces them on the decoded
    public inputs (`build_layer0_wrapper_constraints`). The metadata/reference clauses
    are the satisfied form of the `or(is_dummy, matches)` constraint and the first-real
    scan; the nullifier/exit clauses are the `select`/grouping outputs. -/
structure Layer0Circuit (ro : RandomOracle) (leaves : List LeafPublic)
    (us : List (List Felt)) (out : Layer0Output) : Prop where
  /-- One dummy-nullifier preimage per leaf slot. -/
  uslen : us.length = leaves.length
  /-- Per-slot `select(is_dummy, H(H u), real)`. -/
  nulls : out.nullifiers = buildNullifiers ro leaves us
  /-- The `2N` settled slots are the in-circuit group/dedup of every child's outputs. -/
  exits : out.exitSlots = groupExits (childPairs leaves)
  /-- Each non-dummy child agrees with the aggregate header (the `or`-clause, satisfied). -/
  metaOk : metadataConsistent leaves out
  /-- The header is taken from the first non-dummy child (first-real scan result). -/
  ref : referenceFromFirstReal leaves out

/-- **Layer-0 bridge.** The wrapper constraints imply the spec relation `RL0`. -/
theorem layer0_bridge {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : Layer0Output}
    (h : Layer0Circuit ro leaves us out) : RL0 ro leaves us out := by
  refine ⟨h.metaOk, h.ref, ?_, ?_, h.exits⟩
  · rw [h.nulls]; exact nullifiersReplaced_build ro leaves us h.uslen
  · rw [h.nulls]; exact buildNullifiers_length ro leaves us h.uslen

/-- **Layer-0 soundness (end to end).** A satisfied layer-0 aggregation circuit whose
    recursion gadget accepted every child leaf proof attests both the layer-0 relation
    `RL0` *and* that each child's public inputs satisfy the leaf relation `Rleaf`
    (the latter via the trusted `leaf_proof_sound`). -/
theorem layer0_sound {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : Layer0Output}
    (hacc : ∀ p ∈ leaves, LeafProofAccepted ro p)
    (hcirc : Layer0Circuit ro leaves us out) :
    RL0 ro leaves us out ∧ ∀ p ∈ leaves, ∃ w : LeafWitness, Rleaf ro p w :=
  ⟨layer0_bridge hcirc, fun p hp => leaf_proof_sound ro p (hacc p hp)⟩

/-! ### Layer-1 -/

/-- The layer-1 wrapper constraints (`build_layer1_wrapper_constraints`): bind the
    aggregator address, enforce metadata consistency across the inner layer-0 outputs,
    and forward the exit slots / nullifiers in order. -/
structure Layer1Circuit (ro : RandomOracle) (inner : List Layer0Output)
    (addr : Digest) (out : Layer1Output) : Prop where
  addrEq : out.aggregatorAddress = addr
  metaOk : ∀ o ∈ inner,
      o.assetId = out.assetId ∧ o.volumeFeeBps = out.volumeFeeBps ∧
      o.blockHash = out.blockHash ∧ o.blockNumber = out.blockNumber
  exits : out.exitSlots = (inner.map (fun o => o.exitSlots)).flatten
  nulls : out.nullifiers = (inner.map (fun o => o.nullifiers)).flatten

/-- **Layer-1 bridge.** The wrapper constraints imply the spec relation `RL1`. -/
theorem layer1_bridge {ro : RandomOracle} {inner : List Layer0Output}
    {addr : Digest} {out : Layer1Output}
    (h : Layer1Circuit ro inner addr out) : RL1 ro inner addr out :=
  ⟨h.addrEq, h.metaOk, h.exits, h.nulls⟩

/-- **Layer-1 soundness (end to end).** A satisfied layer-1 aggregation circuit whose
    recursion gadget accepted every inner layer-0 proof attests both `RL1` *and* that
    each inner output satisfies `RL0` for some children (via `layer0_proof_sound`). -/
theorem layer1_sound {ro : RandomOracle} {inner : List Layer0Output}
    {addr : Digest} {out : Layer1Output}
    (hacc : ∀ o ∈ inner, Layer0ProofAccepted ro o)
    (hcirc : Layer1Circuit ro inner addr out) :
    RL1 ro inner addr out ∧ ∀ o ∈ inner, ∃ leaves us, RL0 ro leaves us o :=
  ⟨layer1_bridge hcirc, fun o ho => layer0_proof_sound ro o (hacc o ho)⟩

end WormholeSpec
