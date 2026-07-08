/-
  The aggregation bridge: the private-batch/public-batch wrapper *circuit constraints* imply the spec
  relations `RPrivateBatch` / `RPublicBatch`, and — composed with the trusted recursive-verifier
  soundness (`Trusted.lean`) — a satisfied aggregation circuit attests both its own
  relation and every child's relation.

  WHAT THIS MODELS. We model the wrapper constraints of `build_private_batch_constraints`
  / `build_public_batch_constraints` as the facts the circuit *enforces* on the
  decoded public inputs (`PrivateBatchCircuit` / `PublicBatchCircuit`), then prove each implies
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
  aggregate output satisfies `RPrivateBatch` / `RPublicBatch`.

  SCOPE / ASSURANCE (read honestly). With gadget-level faithfulness delegated to
  `Plonky2Spec.Wrapper` and proof-system soundness to `Trusted.lean`, the theorems
  *here* are deliberately thin, and that should be stated plainly:

    * `private_batch_bridge` does one piece of real work — relating the *functional*
      `buildNullifiers` the circuit computes to the *relational* `nullifiersReplaced`
      (`nullifiersReplaced_build`); its other conjuncts (`metaOk`, `ref`, `exits`) are
      shared verbatim with `RPrivateBatch`. So `private_batch_sound` is "the `private_batch_proof_sound` axiom
      + that one modest nullifier lemma".
    * `public_batch_bridge` is the *identity*. The public-batch wrapper conditions are
      field-for-field `RPublicBatch`, so `PublicBatchCircuit` is *defined as* `RPublicBatch` (below) rather than
      restated, and the bridge carries no logical content. Consequently `public_batch_sound`
      is "the `private_batch_proof_sound` axiom + a structural repackaging" — near-trivial as
      currently scoped.

  This is the intended package boundary, not an oversight; the non-trivial content lives
  in `Plonky2Spec.Wrapper` (gadgets), `Trusted.lean` (proof-system soundness), and the
  private-batch grouping/conservation proofs in `Aggregation.lean`.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf
import WormholeSpec.Aggregation
import WormholeSpec.Trusted

namespace WormholeSpec

/-! ### Private-batch -/

/-- The per-slot nullifier output the circuit builds: `select(is_dummy, H(H u), real)`
    for each `(child, preimage)` pair. Mirrors `nullifiersReplaced`'s per-slot body. -/
def buildNullifiers (ro : RandomOracle) :
    List LeafPublic → List (List Felt) → List Digest
  | [], _ => []
  | _, [] => []
  | p :: ps, u :: us =>
      (if isDummyPrivateBatch p then ro.dummyNull u else p.nullifier) :: buildNullifiers ro ps us

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

/-- The private-batch wrapper constraints, as the circuit enforces them on the decoded
    public inputs (`build_private_batch_constraints`). The metadata/reference clauses
    are the satisfied form of the `or(is_dummy, matches)` constraint and the first-real
    scan; the nullifier/exit clauses are the `select`/grouping outputs. -/
structure PrivateBatchCircuit (ro : RandomOracle) (leaves : List LeafPublic)
    (us : List (List Felt)) (out : PrivateBatchOutput) : Prop where
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

/-- **Private-batch bridge.** The wrapper constraints imply the spec relation `RPrivateBatch`. -/
theorem private_batch_bridge {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput}
    (h : PrivateBatchCircuit ro leaves us out) : RPrivateBatch ro leaves us out := by
  refine ⟨h.metaOk, h.ref, ?_, ?_, h.exits⟩
  · rw [h.nulls]; exact nullifiersReplaced_build ro leaves us h.uslen
  · rw [h.nulls]; exact buildNullifiers_length ro leaves us h.uslen

/-- **Private-batch soundness (end to end).** A satisfied private-batch aggregation circuit whose
    recursion gadget accepted every child leaf proof attests both the private-batch relation
    `RPrivateBatch` *and* that each child's public inputs satisfy the leaf relation `Rleaf`
    (the latter via the trusted `leaf_proof_sound`).

    Honestly scoped, this is "the `leaf_proof_sound` axiom + `private_batch_bridge`", and the
    only real work inside the bridge is `nullifiersReplaced_build` (the rest of `RPrivateBatch` is
    shared verbatim with `PrivateBatchCircuit`). -/
theorem private_batch_sound {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput}
    (hacc : ∀ p ∈ leaves, LeafProofAccepted ro p)
    (hcirc : PrivateBatchCircuit ro leaves us out) :
    RPrivateBatch ro leaves us out ∧ ∀ p ∈ leaves, ∃ w : LeafWitness, Rleaf ro p w :=
  ⟨private_batch_bridge hcirc, fun p hp => leaf_proof_sound ro p (hacc p hp)⟩

/-! ### Public-batch -/

/-- The public-batch wrapper constraints (`build_public_batch_constraints`): bind the
    aggregator address, enforce metadata consistency across the inner private-batch outputs,
    and forward the exit slots / nullifiers in order.

    Unlike layer 0 — where the circuit's *functional* `buildNullifiers` has to be related
    to the *relational* `nullifiersReplaced` (`nullifiersReplaced_build`, the real work)
    — the public-batch wrapper performs no functional decode: the four conditions it enforces
    are *exactly* the four conjuncts of the spec relation `RPublicBatch`. To avoid restating that
    body in two places (which would let the circuit predicate and the relation drift), we
    *define* `PublicBatchCircuit` as `RPublicBatch` itself rather than as a separate structure; the
    `public_batch_bridge` below is then honestly the identity. -/
abbrev PublicBatchCircuit (_ro : RandomOracle) (inner : List PrivateBatchOutput)
    (addr : Digest) (out : PublicBatchOutput) : Prop :=
  RPublicBatch _ro inner addr out

/-- **Public-batch bridge.** Definitionally the identity (`PublicBatchCircuit` *is* `RPublicBatch`): the
    public-batch wrapper enforces precisely `RPublicBatch`'s conjuncts, with no functional decode to
    relate (contrast `private_batch_bridge`, which must invoke `nullifiersReplaced_build`). Kept
    only for naming parity with `private_batch_bridge`; it carries no logical content. -/
theorem public_batch_bridge {ro : RandomOracle} {inner : List PrivateBatchOutput}
    {addr : Digest} {out : PublicBatchOutput}
    (h : PublicBatchCircuit ro inner addr out) : RPublicBatch ro inner addr out := h

/-- **Public-batch soundness (end to end).** A satisfied public-batch aggregation circuit whose
    recursion gadget accepted every inner private-batch proof attests both `RPublicBatch` *and* that
    each inner output satisfies `RPrivateBatch` for some children (via `private_batch_proof_sound`).

    As currently scoped this is near-trivial: the `RPublicBatch` half is `public_batch_bridge` (the
    identity above), so the only substantive content is the trusted `private_batch_proof_sound`
    axiom. The structural faithfulness of the public-batch wrapper gadgets lives in
    `Plonky2Spec.Wrapper`, not here. -/
theorem public_batch_sound {ro : RandomOracle} {inner : List PrivateBatchOutput}
    {addr : Digest} {out : PublicBatchOutput}
    (hacc : ∀ o ∈ inner, PrivateBatchProofAccepted ro o)
    (hcirc : PublicBatchCircuit ro inner addr out) :
    RPublicBatch ro inner addr out ∧ ∀ o ∈ inner, ∃ leaves us, RPrivateBatch ro leaves us o :=
  ⟨public_batch_bridge hcirc, fun o ho => private_batch_proof_sound ro o (hacc o ho)⟩

end WormholeSpec
