/-
  Private-batch and public-batch aggregation relations.

  These capture the wrapper constraints in `build_private_batch_constraints` and
  `build_public_batch_constraints`:

    * metadata consistency across non-dummy children (asset_id, fee, block);
    * one fee inequality over the dummy-masked input/output totals of the whole
      private segment;
    * the block reference being taken from the first non-dummy slot (the
      position-independent selection from the `illuzen/full-shuffle` fix), with
      an all-dummy batch settling to a zero block hash;
    * dummy-nullifier replacement `DNull(u) = H(H(u))`;
    * the nullifier region emitted as a privately witnessed permutation of the
      per-slot selections: every selected digest is preserved exactly, while
      its public output position need not match its producing leaf slot;
    * the exit *grouping/dedup* primitive (`groupExits`) that builds the `2N`
      settled slots, fed the *dummy-masked* child pairs (`maskedChildPairs`):
      the circuit masks each dummy slot's (exit account, amount) to `(0, 0)`
      at ingress, because leaf exit accounts are unconstrained public inputs
      and a poisoned padding template could otherwise mark padded slots with
      attacker-chosen zero-amount exits (audit finding: incomplete dummy
      sentinel);
    * pairwise distinctness of the *real* slots' nullifiers
      (`realNullifiersDistinct`): the anti-replay constraint. Because the exit
      grouping sums amounts across slots, one leaf proof replayed into `k` slots
      would settle `k·amount` against a single on-chain nullifier; the circuit
      makes such a batch unprovable, and `RPrivateBatch_settles_distinct_spends`
      is the theorem that constraint exists for;
    * the slot-count header `numExitSlots = 2·N` (a circuit constant).

  Exit conservation is not separately asserted: `RPrivateBatch` pins the exact
  in-circuit grouping over the masked pairs, and
  `outputExitTotal = maskedOutputTotal` is *derived* as
  `RPrivateBatch_value_conservation`. Economic conservation is the primitive
  segment-level predicate `privateBatchFeeOk`: unlike the old leaf-local rule,
  it permits value pooling between real leaves in the same private segment.

  NOTE the *weaker* private-batch dummy sentinel: at layer 0 a child is treated as a
  dummy when `block_hash == 0` alone (`isDummyPrivateBatch`), versus the leaf circuit's
  `block_hash == 0 ∧ outputs == 0`. The ingress mask makes the exit region
  independent of that gap (a masked dummy contributes `(0, 0)` regardless of what
  the leaf carried), so conservation no longer needs the leaf↔private-batch
  compatibility hypothesis; `rawOutputTotal_eq_maskedOutputTotal` keeps the
  compatibility statement (dummy ⟹ zero outputs) available for a full
  composition proof.

  AGGREGATE FEES OVER `Nat` VS `ZMod p` (a Phase-2 caveat)
  --------------------------------------------------------
  `RPrivateBatch_value_conservation` is an *exact* `Nat` identity, so it is economically
  meaningful as stated. The fee comparison is also a `Nat` inequality, while the
  circuit computes both scaled sides and their difference in the Goldilocks
  field. Merely proving the unscaled totals `< goldilocks` is therefore
  insufficient: both `maskedOutputTotal * 10000` and
  `maskedInputTotal * (10000 - fee_bps)` must not wrap.

  The bounds below make that obligation explicit. They first bound raw and
  masked totals linearly, then prove the two scaled sides are below
  `goldilocks` for at most 64 children with 32-bit amounts.

  The circuit enforces the inequality as `range_check(rhs − lhs, 52)` over the
  field. That check is sound by a *two-sided* argument, and `lhs < p` alone is
  not enough for it: (i) an honest `rhs ≥ lhs` gives `rhs − lhs ≤ rhs < 2^52`
  (`privateBatchFeeRhs_lt_two_pow_52`); (ii) a dishonest `rhs < lhs` wraps to
  `p − (lhs − rhs) ≥ p − lhs`, which must land *above* `2^52`, i.e. `lhs < p − 2^52`
  (`privateBatchFeeLhs_add_two_pow_52_lt_modulus`). Note `lhs` itself can exceed
  `2^52` (`128 · (2³² − 1) · 10⁴ ≈ 5.5·10¹⁵ > 2^52 ≈ 4.5·10¹⁵`), so (ii) really is
  the "wrapped difference lands near `p`" argument, not "`lhs` fits in 52 bits".
  The field-level lift of these two bounds through the range-check gadget is the
  `Plonky2Spec` obligation; the `Nat` bounds here are its side conditions.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf

namespace WormholeSpec

/-- One settled exit slot: a grouped sum and its destination account. -/
structure ExitSlot where
  sum : Felt
  account : Digest
  deriving Repr

/-- Public output of a private-batch aggregation proof (see `aggregated_output`). -/
structure PrivateBatchOutput where
  numExitSlots : Felt
  assetId : Felt
  volumeFeeBps : Felt
  blockHash : Digest
  blockNumber : Felt
  exitSlots : List ExitSlot
  nullifiers : List Digest

/-- Private-batch dummy sentinel: `block_hash == 0` (weaker than the leaf's notion).
    `abbrev` (reducible) so `Decidable` resolves through it via `DecidableEq Digest`. -/
abbrev isDummyPrivateBatch (p : LeafPublic) : Prop := p.blockHash = Digest.zero

/-- Boolean "is a real (non-dummy) child", for use with `List.find?`. -/
def isRealB (p : LeafPublic) : Bool := ! decide (isDummyPrivateBatch p)

/-- Total input amount over every child, dummies included. Used to bound the
    dummy-masked input accumulator. -/
def rawInputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest => p.inputAmount + rawInputTotal rest

/-- Total of the two output amounts over *every* child, dummies included
    (unmasked). Used for no-wraparound bounds and the leaf-compatibility
    statement. -/
def rawOutputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest => (p.outputAmount1 + p.outputAmount2) + rawOutputTotal rest

/-- Input total restricted to real children, exactly matching the private-batch
    circuit's dummy-masked input accumulator. -/
def maskedInputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest =>
      (if isDummyPrivateBatch p then 0 else p.inputAmount) + maskedInputTotal rest

/-- Output total restricted to real children, exactly matching the
    private-batch circuit's dummy-masked output accumulator and the amount fed
    to exit grouping. -/
def maskedOutputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest =>
      (if isDummyPrivateBatch p then 0 else p.outputAmount1 + p.outputAmount2) +
        maskedOutputTotal rest

/-- Basis-point denominator used by the private-batch fee constraint. -/
def feeDenominator : Felt := 10000

/-- One fee/value-conservation check for an entire private segment. Dummy child
    inputs and outputs do not contribute. The bound on `volumeFeeBps` makes the
    `Nat` subtraction agree with the intended nonnegative field complement. -/
def privateBatchFeeOk (leaves : List LeafPublic) (out : PrivateBatchOutput) : Prop :=
  out.volumeFeeBps ≤ feeDenominator ∧
  maskedOutputTotal leaves * feeDenominator ≤
    maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps)

/-- The flattened `(account, amount)` outputs of all children, two per child,
    with each dummy child's pairs masked to the canonical `(zero, 0)` — exactly
    the slot inputs the circuit feeds the grouping after its ingress mask
    (the `select(is_dummy_i, 0, …)` in `build_private_batch_constraints`).
    The mask exists because leaf exit accounts are unconstrained public
    inputs: a poisoned dummy padding template could otherwise mark padded
    slots with attacker-chosen zero-amount exits (audit finding: incomplete
    dummy sentinel). -/
def maskedChildPairs : List LeafPublic → List (Digest × Felt)
  | [] => []
  | p :: rest =>
      (if isDummyPrivateBatch p then (Digest.zero, 0) else (p.exitAccount1, p.outputAmount1)) ::
      (if isDummyPrivateBatch p then (Digest.zero, 0) else (p.exitAccount2, p.outputAmount2)) ::
      maskedChildPairs rest

/-- Sum of the amounts whose account equals `k`. Mirrors the per-slot
    `select(exit_j = key, amount_j, 0)` accumulation across all slots. -/
def matchSum (k : Digest) : List (Digest × Felt) → Felt
  | [] => 0
  | (k', a') :: rest => (if k' = k then a' else 0) + matchSum k rest

/-- Exit grouping/dedup, exactly as the circuit builds the `2N` output slots:
    walking left to right with the set `seen` of keys already emitted, the first
    occurrence of an account gets the full group sum (its own amount plus every
    match further right), and any later occurrence is zeroed (so duplicates are
    indistinguishable from unused slots). -/
def groupAux (seen : List Digest) : List (Digest × Felt) → List ExitSlot
  | [] => []
  | (k, a) :: rest =>
      (if k ∈ seen then ⟨0, Digest.zero⟩ else ⟨a + matchSum k rest, k⟩) ::
        groupAux (k :: seen) rest

/-- Top-level grouping (empty `seen`). -/
def groupExits (xs : List (Digest × Felt)) : List ExitSlot := groupAux [] xs

/-- Sum of the settled exit-slot amounts (the value leaving the batch). -/
def slotsTotal : List ExitSlot → Felt
  | [] => 0
  | s :: rest => s.sum + slotsTotal rest

/-- Sum of amounts over children whose accounts have not been emitted yet; the
    recursive companion of "sum the slots that are first occurrences". -/
def amtNotIn (seen : List Digest) : List (Digest × Felt) → Felt
  | [] => 0
  | (k, a) :: rest => (if k ∈ seen then 0 else a) + amtNotIn seen rest

/-- Sum of the settled exit-slot amounts of a private-batch output. -/
def outputExitTotal (out : PrivateBatchOutput) : Felt := slotsTotal out.exitSlots

/-- Metadata of each non-dummy child agrees with the aggregate header. -/
def metadataConsistent (leaves : List LeafPublic) (out : PrivateBatchOutput) : Prop :=
  ∀ p ∈ leaves, ¬ isDummyPrivateBatch p →
    p.assetId = out.assetId ∧
    p.volumeFeeBps = out.volumeFeeBps ∧
    p.blockHash = out.blockHash ∧
    p.blockNumber = out.blockNumber

/-- The block reference is the first non-dummy child; an all-dummy batch keeps the
    scan's zero initial values for the block hash, block number and fee (and settles
    nothing). `assetId` is taken from slot 0 unconditionally (every slot's asset is
    connected to it, dummies included), so it is not part of the scan. -/
def referenceFromFirstReal (leaves : List LeafPublic) (out : PrivateBatchOutput) : Prop :=
  match leaves.find? isRealB with
  | some p => out.blockHash = p.blockHash ∧ out.blockNumber = p.blockNumber ∧
              out.assetId = p.assetId ∧ out.volumeFeeBps = p.volumeFeeBps
  | none   => out.blockHash = Digest.zero ∧ out.blockNumber = 0 ∧ out.volumeFeeBps = 0

/-- The reference fee is either a real child's fee or the scan's zero, so any bound
    every child's fee satisfies is inherited by the header (used by the field-level
    fee-comparator bridge, which needs `volumeFeeBps < 2^32`). -/
theorem referenceFromFirstReal_volumeFeeBps_lt {leaves : List LeafPublic}
    {out : PrivateBatchOutput} {M : Felt} (hM : 0 < M)
    (href : referenceFromFirstReal leaves out)
    (hfee : ∀ p ∈ leaves, p.volumeFeeBps < M) : out.volumeFeeBps < M := by
  unfold referenceFromFirstReal at href
  split at href
  · next p hp =>
      rw [href.2.2.2]
      exact hfee p (List.mem_of_find?_eq_some hp)
  · rw [href.2.2]; exact hM

/-- Per-slot nullifier output: real children forward `nullifier`; private-batch dummies
    are replaced by `DNull(u)` for the witnessed preimage `u`.

    This is the pre-permutation per-slot correspondence: slot `i` of the list
    relates to leaf `i`. The circuit may emit any permutation of this list (the
    `∃ raw, … ∧ Perm` conjunct of `RPrivateBatch`). -/
def nullifiersReplaced (ro : RandomOracle) :
    List LeafPublic → List (List Felt) → List Digest → Prop
  | [],      [],      []      => True
  | p :: ps, u :: us, n :: ns =>
      (n = if isDummyPrivateBatch p then ro.dummyNull u else p.nullifier) ∧
      nullifiersReplaced ro ps us ns
  | _,       _,       _       => False

/-- **Real-nullifier uniqueness (anti-replay).** No two *real* slots carry the same
    nullifier. Mirrors the circuit's pairwise loop over `i < j`:
    `and(and(is_real_i, is_real_j), digest_eq(null_i, null_j)) = 0`. Stated as
    `List.Pairwise` so that slot order is exactly the circuit's slot order; dummy
    slots are exempt (their nullifiers are replaced by `DNull(u)` and never settle). -/
def realNullifiersDistinct (leaves : List LeafPublic) : Prop :=
  leaves.Pairwise fun p q =>
    ¬ isDummyPrivateBatch p → ¬ isDummyPrivateBatch q → p.nullifier ≠ q.nullifier

/-- The real (non-dummy) children of a batch, in slot order. -/
def realLeaves (leaves : List LeafPublic) : List LeafPublic := leaves.filter isRealB

/-- The nullifiers the real children actually spend, in slot order. -/
def realNullifiers (leaves : List LeafPublic) : List Digest :=
  (realLeaves leaves).map LeafPublic.nullifier

/--
`RPrivateBatch ro leaves us out` holds iff the private-batch wrapper accepts children `leaves`
with dummy-nullifier preimages `us`, producing aggregate output `out`.

`us` has one entry per child (used only on dummy slots). This matches the circuit
witness layout exactly: `PrivateBatchCircuitTargets.dummy_nullifier_pre_images` is a
`Vec<[Target; 4]>` allocated once *per leaf slot* (`for _ in 0..n_leaf`), not once
per dummy — see `private_batch/circuit/circuit_logic.rs:46–47, 76–85`. The wrapper reads
slot `i`'s preimage only when slot `i` is a dummy (`select(is_dummy_i, …)`), so the
per-child length bookkeeping here (`out.nullifiers.length = leaves.length`) lines up
with the circuit (permutation preserves length).

NULLIFIER ORDERING. The circuit routes the per-slot selections through private
boolean switches before registering them. The public output is therefore any
permutation chosen by the local prover, while the `Perm` relation proves exact
multiset preservation. The permutation witness is not part of the public
output.
-/
def RPrivateBatch (ro : RandomOracle) (leaves : List LeafPublic) (us : List (List Felt))
    (out : PrivateBatchOutput) : Prop :=
  metadataConsistent leaves out ∧
  referenceFromFirstReal leaves out ∧
  (∃ raw, nullifiersReplaced ro leaves us raw ∧ out.nullifiers.Perm raw) ∧
  out.nullifiers.length = leaves.length ∧
  privateBatchFeeOk leaves out ∧
  -- Primitive exit construction: the settled slots are *exactly* the in-circuit
  -- group/dedup of every child's two (account, amount) outputs, with dummy
  -- children masked to `(zero, 0)` at ingress (see `maskedChildPairs`). Value
  -- exit conservation is a derived theorem (`RPrivateBatch_value_conservation`);
  -- economic conservation is the segment-level `privateBatchFeeOk` conjunct.
  out.exitSlots = groupExits (maskedChildPairs leaves) ∧
  -- Anti-replay: real slots spend pairwise-distinct nullifiers.
  realNullifiersDistinct leaves ∧
  -- Slot-count header (`num_exit_slots_t = constant(2 · n_leaf)`).
  out.numExitSlots = 2 * leaves.length

-- ── Exit-grouping conservation, derived from the primitive ──────────────────

/-- Re-protecting a key already in `seen` changes nothing. -/
theorem amtNotIn_cons_mem {k : Digest} {seen : List Digest} (hk : k ∈ seen) :
    ∀ xs, amtNotIn (k :: seen) xs = amtNotIn seen xs := by
  intro xs
  induction xs with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨k', a'⟩ := hd
      have hiff : (k' ∈ k :: seen) ↔ (k' ∈ seen) := by
        constructor
        · intro h
          rcases List.mem_cons.1 h with h' | h'
          · exact h' ▸ hk
          · exact h'
        · intro h; exact List.mem_cons.2 (Or.inr h)
      simp only [amtNotIn, ih]
      by_cases hc : k' ∈ seen
      · rw [if_pos hc, if_pos (hiff.2 hc)]
      · rw [if_neg hc, if_neg (fun h => hc (hiff.1 h))]

/-- The accumulator identity behind conservation: summing the matches of a fresh
    key `k` (not yet in `seen`) plus the remaining not-yet-seen amounts equals
    the not-yet-seen amounts without protecting `k`. -/
theorem matchSum_amtNotIn {k : Digest} {seen : List Digest} (hk : k ∉ seen) :
    ∀ xs, matchSum k xs + amtNotIn (k :: seen) xs = amtNotIn seen xs := by
  intro xs
  induction xs with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨k', a'⟩ := hd
      simp only [matchSum, amtNotIn]
      by_cases hkk : k' = k
      · subst hkk
        rw [if_pos rfl, if_pos List.mem_cons_self, if_neg hk]
        simp only [Felt] at *; omega
      · by_cases hs : k' ∈ seen
        · rw [if_neg hkk, if_pos (List.mem_cons.2 (Or.inr hs)), if_pos hs]
          simp only [Felt] at *; omega
        · have h2 : k' ∉ k :: seen := by
            intro h
            rcases List.mem_cons.1 h with h' | h'
            · exact hkk h'
            · exact hs h'
          rw [if_neg hkk, if_neg h2, if_neg hs]
          simp only [Felt] at *; omega

/-- The grouping conserves value: the settled slot total equals the total of all
    not-yet-seen child amounts. -/
theorem groupAux_conserves :
    ∀ (seen : List Digest) (xs : List (Digest × Felt)),
      slotsTotal (groupAux seen xs) = amtNotIn seen xs := by
  intro seen xs
  induction xs generalizing seen with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨k, a⟩ := hd
      by_cases hk : k ∈ seen
      · have e1 : groupAux seen ((k, a) :: tl)
            = (⟨0, Digest.zero⟩ : ExitSlot) :: groupAux (k :: seen) tl := by
          simp only [groupAux, if_pos hk]
        rw [e1]
        show (0 : Felt) + slotsTotal (groupAux (k :: seen) tl)
            = amtNotIn seen ((k, a) :: tl)
        rw [ih (k :: seen), amtNotIn_cons_mem hk tl]
        have hR : amtNotIn seen ((k, a) :: tl) = 0 + amtNotIn seen tl := by
          simp only [amtNotIn, if_pos hk]
        rw [hR]
      · have e1 : groupAux seen ((k, a) :: tl)
            = (⟨a + matchSum k tl, k⟩ : ExitSlot) :: groupAux (k :: seen) tl := by
          simp only [groupAux, if_neg hk]
        have hm := matchSum_amtNotIn hk tl
        rw [e1]
        show (a + matchSum k tl) + slotsTotal (groupAux (k :: seen) tl)
            = amtNotIn seen ((k, a) :: tl)
        rw [ih (k :: seen)]
        have hR : amtNotIn seen ((k, a) :: tl) = a + amtNotIn seen tl := by
          simp only [amtNotIn, if_neg hk]
        rw [hR]; simp only [Felt] at *; omega

/-- `amtNotIn []` over the masked pairs is the non-dummy output total. -/
theorem amtNotIn_nil_maskedChildPairs (leaves : List LeafPublic) :
    amtNotIn [] (maskedChildPairs leaves) = maskedOutputTotal leaves := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      by_cases hd : isDummyPrivateBatch p
      · have e : maskedChildPairs (p :: rest)
            = (Digest.zero, 0) :: (Digest.zero, 0) :: maskedChildPairs rest := by
          simp only [maskedChildPairs, if_pos hd]
        have hR : maskedOutputTotal (p :: rest) = 0 + maskedOutputTotal rest := by
          simp only [maskedOutputTotal, if_pos hd]
        rw [e, hR]
        show (0 : Felt) + ((0 : Felt) + amtNotIn [] (maskedChildPairs rest))
            = 0 + maskedOutputTotal rest
        rw [ih]; simp only [Felt] at *; omega
      · have e : maskedChildPairs (p :: rest)
            = (p.exitAccount1, p.outputAmount1) ::
              (p.exitAccount2, p.outputAmount2) :: maskedChildPairs rest := by
          simp only [maskedChildPairs, if_neg hd]
        have hR : maskedOutputTotal (p :: rest)
            = (p.outputAmount1 + p.outputAmount2) + maskedOutputTotal rest := by
          simp only [maskedOutputTotal, if_neg hd]
        rw [e, hR]
        show p.outputAmount1 + (p.outputAmount2 + amtNotIn [] (maskedChildPairs rest))
            = (p.outputAmount1 + p.outputAmount2) + maskedOutputTotal rest
        rw [ih]; simp only [Felt] at *; omega

/-- Conservation for the top-level grouping of the masked children's outputs. -/
theorem groupExits_maskedChildPairs (leaves : List LeafPublic) :
    slotsTotal (groupExits (maskedChildPairs leaves)) = maskedOutputTotal leaves := by
  unfold groupExits
  rw [groupAux_conserves [] (maskedChildPairs leaves), amtNotIn_nil_maskedChildPairs]

/-- **Exit-grouping conservation:** every private-batch output settles exactly
    the declared output total of its real children. This is distinct from
    economic input/output conservation, which follows from `privateBatchFeeOk`.
    The grouping runs over dummy-masked pairs, so no leaf↔private-batch
    compatibility hypothesis (dummy ⟹ zero outputs) is needed. -/
theorem RPrivateBatch_value_conservation {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out = maskedOutputTotal leaves := by
  unfold outputExitTotal
  rw [h.2.2.2.2.2.1]
  exact groupExits_maskedChildPairs leaves

-- ── Slot accounting ─────────────────────────────────────────────────────────

/-- Grouping preserves the slot count: one settled slot per `(account, amount)` pair. -/
theorem groupAux_length (seen : List Digest) :
    ∀ xs : List (Digest × Felt), (groupAux seen xs).length = xs.length := by
  intro xs
  induction xs generalizing seen with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨k, a⟩ := hd
      simp only [groupAux, List.length_cons, ih]

/-- Two masked pairs per child. -/
theorem maskedChildPairs_length (leaves : List LeafPublic) :
    (maskedChildPairs leaves).length = 2 * leaves.length := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      simp only [maskedChildPairs, List.length_cons, ih]
      omega

/-- The settled exit region has exactly `2·N` slots, so the `numExitSlots` header the
    circuit emits as a constant is the length of the region it describes. -/
theorem RPrivateBatch_exitSlots_length {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    out.exitSlots.length = out.numExitSlots := by
  rw [h.2.2.2.2.2.1, h.2.2.2.2.2.2.2]
  unfold groupExits
  rw [groupAux_length, maskedChildPairs_length]

-- ── Real-nullifier uniqueness: one spend per settled leaf ───────────────────

theorem isRealB_true_iff {p : LeafPublic} : isRealB p = true ↔ ¬ isDummyPrivateBatch p := by
  unfold isRealB
  by_cases hd : isDummyPrivateBatch p
  · rw [decide_eq_true hd]; exact ⟨fun h => Bool.noConfusion h, fun h => absurd hd h⟩
  · rw [decide_eq_false hd]; exact ⟨fun _ => hd, fun _ => rfl⟩

theorem isRealB_false_iff {p : LeafPublic} : isRealB p = false ↔ isDummyPrivateBatch p := by
  unfold isRealB
  by_cases hd : isDummyPrivateBatch p
  · rw [decide_eq_true hd]; exact ⟨fun _ => hd, fun _ => rfl⟩
  · rw [decide_eq_false hd]; exact ⟨fun h => Bool.noConfusion h, fun h => absurd h hd⟩

/-- `Pairwise` restricted along `filter`: the real children inherit the pairwise
    property with the dummy guards discharged. -/
theorem realLeaves_pairwise_ne {leaves : List LeafPublic} (h : realNullifiersDistinct leaves) :
    (realLeaves leaves).Pairwise fun p q => p.nullifier ≠ q.nullifier := by
  unfold realLeaves
  have hsub := List.Pairwise.filter (p := isRealB) h
  refine hsub.imp_of_mem ?_
  intro p q hp hq hpq
  exact hpq (isRealB_true_iff.mp (List.mem_filter.1 hp).2)
    (isRealB_true_iff.mp (List.mem_filter.1 hq).2)

/-- The nullifiers spent by the real children are pairwise distinct. -/
theorem realNullifiersDistinct_nodup {leaves : List LeafPublic}
    (h : realNullifiersDistinct leaves) : (realNullifiers leaves).Nodup := by
  unfold realNullifiers List.Nodup
  rw [List.pairwise_map]
  exact realLeaves_pairwise_ne h

/-- A real child's nullifier is forwarded verbatim into the pre-permutation list. -/
theorem nullifiersReplaced_real_mem (ro : RandomOracle) :
    ∀ (leaves : List LeafPublic) (us : List (List Felt)) (raw : List Digest),
      nullifiersReplaced ro leaves us raw →
      ∀ p ∈ leaves, ¬ isDummyPrivateBatch p → p.nullifier ∈ raw
  | [], _, _, _, _, hp, _ => absurd hp List.not_mem_nil
  | q :: qs, u :: us, n :: ns, ⟨hn, hrest⟩, p, hp, hreal => by
      rcases List.mem_cons.1 hp with hpq | hpq
      · subst hpq
        rw [hn, if_neg hreal]
        exact List.mem_cons_self
      · exact List.mem_cons_of_mem _
          (nullifiersReplaced_real_mem ro qs us ns hrest p hpq hreal)
  | _ :: _, [], _, h, _, _, _ => nomatch h
  | _ :: _, _ :: _, [], h, _, _, _ => nomatch h

/-- A real child's nullifier reaches the output region (through the private permutation). -/
theorem RPrivateBatch_real_nullifier_mem {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    ∀ p ∈ leaves, ¬ isDummyPrivateBatch p → p.nullifier ∈ out.nullifiers := by
  obtain ⟨raw, hrep, hperm⟩ := h.2.2.1
  intro p hp hreal
  exact hperm.symm.mem_iff.mp (nullifiersReplaced_real_mem ro leaves us raw hrep p hp hreal)

/-- The masked output total is the raw output total of the real children alone. -/
theorem maskedOutputTotal_eq_rawOutputTotal_realLeaves (leaves : List LeafPublic) :
    maskedOutputTotal leaves = rawOutputTotal (realLeaves leaves) := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      by_cases hd : isDummyPrivateBatch p
      · have hf : isRealB p = false := isRealB_false_iff.mpr hd
        have e1 : maskedOutputTotal (p :: rest) = 0 + maskedOutputTotal rest := by
          simp only [maskedOutputTotal, if_pos hd]
        have e2 : realLeaves (p :: rest) = realLeaves rest := by
          simp only [realLeaves, List.filter_cons, hf, Bool.false_eq_true, if_false]
        rw [e1, e2, ih, Nat.zero_add]
      · have ht : isRealB p = true := isRealB_true_iff.mpr hd
        have e1 : maskedOutputTotal (p :: rest)
            = (p.outputAmount1 + p.outputAmount2) + maskedOutputTotal rest := by
          simp only [maskedOutputTotal, if_neg hd]
        have e2 : realLeaves (p :: rest) = p :: realLeaves rest := by
          simp only [realLeaves, List.filter_cons, ht, if_true]
        rw [e1, e2, rawOutputTotal, ih]

/-- **One spend per settled leaf.** The value a private batch settles is the output total
    of its real children, and those children spend pairwise-distinct nullifiers — so no
    leaf proof is counted twice against a single on-chain nullifier. This is the property
    the uniqueness constraint was added to protect (the replay-inflation finding). -/
theorem RPrivateBatch_settles_distinct_spends {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out = rawOutputTotal (realLeaves leaves) ∧ (realNullifiers leaves).Nodup :=
  ⟨(RPrivateBatch_value_conservation h).trans
      (maskedOutputTotal_eq_rawOutputTotal_realLeaves leaves),
    realNullifiersDistinct_nodup h.2.2.2.2.2.2.1⟩

/-- The masked input total is bounded by the raw input total. -/
theorem maskedInputTotal_le_rawInputTotal (leaves : List LeafPublic) :
    maskedInputTotal leaves ≤ rawInputTotal leaves := by
  induction leaves with
  | nil => exact Nat.le_refl 0
  | cons p rest ih =>
      by_cases hd : isDummyPrivateBatch p
      · simp only [maskedInputTotal, rawInputTotal, if_pos hd]
        simp only [Felt] at *; omega
      · simp only [maskedInputTotal, rawInputTotal, if_neg hd]
        simp only [Felt] at *; omega

/-- The masked output total is bounded by the raw output total. -/
theorem maskedOutputTotal_le_rawOutputTotal (leaves : List LeafPublic) :
    maskedOutputTotal leaves ≤ rawOutputTotal leaves := by
  induction leaves with
  | nil => exact Nat.le_refl 0
  | cons p rest ih =>
      by_cases hd : isDummyPrivateBatch p
      · simp only [maskedOutputTotal, rawOutputTotal, if_pos hd]
        simp only [Felt] at *; omega
      · simp only [maskedOutputTotal, rawOutputTotal, if_neg hd]
        simp only [Felt] at *; omega

-- ── Aggregate-fee consequences and no-wraparound bounds ─────────────────────

/-- The primitive relation exposes the private-segment fee inequality. -/
theorem RPrivateBatch_fee_conservation {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    maskedOutputTotal leaves * feeDenominator ≤
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) :=
  h.2.2.2.2.1.2

/-- A valid private segment has a well-formed basis-point rate. -/
theorem RPrivateBatch_fee_bps_bound {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    out.volumeFeeBps ≤ feeDenominator :=
  h.2.2.2.2.1.1

/-- Aggregate fee conservation implies that real outputs cannot exceed real
    inputs, independently of how value is pooled among leaves. -/
theorem privateBatchFeeOk_output_le_input {leaves : List LeafPublic}
    {out : PrivateBatchOutput} (h : privateBatchFeeOk leaves out) :
    maskedOutputTotal leaves ≤ maskedInputTotal leaves := by
  have hcomp : feeDenominator - out.volumeFeeBps ≤ feeDenominator := Nat.sub_le _ _
  have hrhs :
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) ≤
        maskedInputTotal leaves * feeDenominator :=
    Nat.mul_le_mul_left _ hcomp
  have hscaled := Nat.le_trans h.2 hrhs
  exact Nat.le_of_mul_le_mul_right hscaled (by unfold feeDenominator; omega)

/-- Relation-level corollary: total real outputs do not exceed total real
    inputs. This is weaker than the fee inequality but useful to callers. -/
theorem RPrivateBatch_output_le_input {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    maskedOutputTotal leaves ≤ maskedInputTotal leaves :=
  privateBatchFeeOk_output_le_input h.2.2.2.2.1

/-- The settled exit total itself satisfies the aggregate fee inequality. This
    composes the primitive fee check with derived exit-grouping conservation. -/
theorem RPrivateBatch_settlement_fee_conservation {ro : RandomOracle}
    {leaves : List LeafPublic} {us : List (List Felt)} {out : PrivateBatchOutput}
    (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out * feeDenominator ≤
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) := by
  rw [RPrivateBatch_value_conservation h]
  exact RPrivateBatch_fee_conservation h

/-- Consequently, the amount actually settled by a private segment cannot
    exceed that segment's total real input. -/
theorem RPrivateBatch_settlement_le_input {ro : RandomOracle}
    {leaves : List LeafPublic} {us : List (List Felt)} {out : PrivateBatchOutput}
    (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out ≤ maskedInputTotal leaves := by
  rw [RPrivateBatch_value_conservation h]
  exact RPrivateBatch_output_le_input h

/-- A per-input bound `M` lifts to a linear bound on the raw input total. -/
theorem rawInputTotal_le_linear {leaves : List LeafPublic} {M : Felt}
    (h : ∀ p ∈ leaves, p.inputAmount ≤ M) :
    rawInputTotal leaves ≤ leaves.length * M := by
  induction leaves with
  | nil => simp [rawInputTotal]
  | cons p rest ih =>
      have hp := h p List.mem_cons_self
      have ihrest := ih (fun q hq => h q (List.mem_cons_of_mem _ hq))
      have hexp : (rest.length + 1) * M = rest.length * M + M := Nat.succ_mul _ _
      simp only [rawInputTotal, List.length_cons, Felt] at *
      omega

/-- A per-output bound `M` lifts to a linear bound on the raw output total: with each
    of the two outputs `≤ M`, a batch of `n` children totals `≤ n · 2M`. -/
theorem rawOutputTotal_le_linear {leaves : List LeafPublic} {M : Felt}
    (h : ∀ p ∈ leaves, p.outputAmount1 ≤ M ∧ p.outputAmount2 ≤ M) :
    rawOutputTotal leaves ≤ leaves.length * (2 * M) := by
  induction leaves with
  | nil => simp [rawOutputTotal]
  | cons p rest ih =>
      obtain ⟨h1, h2⟩ := h p List.mem_cons_self
      have ihrest := ih (fun q hq => h q (List.mem_cons_of_mem _ hq))
      -- `(n+1)·2M = n·2M + 2M`, so `omega` can treat the products as atoms.
      have hexp : (rest.length + 1) * (2 * M) = rest.length * (2 * M) + 2 * M :=
        Nat.succ_mul _ _
      simp only [rawOutputTotal, List.length_cons, Felt] at *
      omega

/-- The explicit unscaled input no-wraparound bound for the Phase-2 field model. -/
theorem rawInputTotal_lt_modulus {leaves : List LeafPublic} {M : Felt}
    (hM : ∀ p ∈ leaves, p.inputAmount ≤ M)
    (hbatch : leaves.length * M < goldilocks) :
    rawInputTotal leaves < goldilocks :=
  Nat.lt_of_le_of_lt (rawInputTotal_le_linear hM) hbatch

/-- The explicit unscaled output no-wraparound bound that the field model must assume.
    If the linear batch bound stays below the modulus, the `Nat` total does too,
    so reducing mod `goldilocks` is lossless and the `Nat` conservation identity
    transfers verbatim to `ZMod goldilocks`. Under the leaf circuit's 32-bit output
    range checks (`M = 2³² − 1`) the side condition `n · 2M < goldilocks` holds for
    every batch size `n < 2³¹`. -/
theorem rawOutputTotal_lt_modulus {leaves : List LeafPublic} {M : Felt}
    (hM : ∀ p ∈ leaves, p.outputAmount1 ≤ M ∧ p.outputAmount2 ≤ M)
    (hbatch : leaves.length * (2 * M) < goldilocks) :
    rawOutputTotal leaves < goldilocks :=
  Nat.lt_of_le_of_lt (rawOutputTotal_le_linear hM) hbatch

/-- Unscaled no-wraparound for the masked input accumulator. -/
theorem maskedInputTotal_lt_modulus {leaves : List LeafPublic} {M : Felt}
    (hM : ∀ p ∈ leaves, p.inputAmount ≤ M)
    (hbatch : leaves.length * M < goldilocks) :
    maskedInputTotal leaves < goldilocks :=
  Nat.lt_of_le_of_lt (maskedInputTotal_le_rawInputTotal leaves)
    (rawInputTotal_lt_modulus hM hbatch)

/-- Unscaled no-wraparound for the masked output accumulator. -/
theorem maskedOutputTotal_lt_modulus {leaves : List LeafPublic} {M : Felt}
    (hM : ∀ p ∈ leaves, p.outputAmount1 ≤ M ∧ p.outputAmount2 ≤ M)
    (hbatch : leaves.length * (2 * M) < goldilocks) :
    maskedOutputTotal leaves < goldilocks :=
  Nat.lt_of_le_of_lt (maskedOutputTotal_le_rawOutputTotal leaves)
    (rawOutputTotal_lt_modulus hM hbatch)

/-- For the protocol maximum of 64 children and 32-bit inputs, the scaled
    aggregate input side cannot wrap in the Goldilocks field. -/
theorem maskedInputTotal_mul_feeDenominator_lt_modulus {leaves : List LeafPublic}
    (hlen : leaves.length ≤ 64)
    (hM : ∀ p ∈ leaves, inRange 32 p.inputAmount) :
    maskedInputTotal leaves * feeDenominator < goldilocks := by
  have hM' : ∀ p ∈ leaves, p.inputAmount ≤ 2 ^ 32 := by
    intro p hp
    exact Nat.le_of_lt (hM p hp)
  have hraw := rawInputTotal_le_linear hM'
  have hmasked := maskedInputTotal_le_rawInputTotal leaves
  have htotal : maskedInputTotal leaves ≤ leaves.length * (2 ^ 32) :=
    Nat.le_trans hmasked hraw
  have hscaled :
      maskedInputTotal leaves * feeDenominator ≤
        (leaves.length * (2 ^ 32)) * feeDenominator :=
    Nat.mul_le_mul_right _ htotal
  have hcapacity :
      (leaves.length * (2 ^ 32)) * feeDenominator ≤
        (64 * (2 ^ 32)) * feeDenominator := by
    exact Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ hlen)
  have hnumeric : (64 * (2 ^ 32)) * feeDenominator < goldilocks := by
    native_decide
  exact Nat.lt_of_le_of_lt (Nat.le_trans hscaled hcapacity) hnumeric

/-- For the protocol maximum of 64 children and 32-bit outputs, the scaled
    aggregate output side cannot wrap in the Goldilocks field. -/
theorem maskedOutputTotal_mul_feeDenominator_lt_modulus {leaves : List LeafPublic}
    (hlen : leaves.length ≤ 64)
    (hM : ∀ p ∈ leaves,
      inRange 32 p.outputAmount1 ∧ inRange 32 p.outputAmount2) :
    maskedOutputTotal leaves * feeDenominator < goldilocks := by
  have hM' : ∀ p ∈ leaves,
      p.outputAmount1 ≤ 2 ^ 32 ∧ p.outputAmount2 ≤ 2 ^ 32 := by
    intro p hp
    obtain ⟨h1, h2⟩ := hM p hp
    exact ⟨Nat.le_of_lt h1, Nat.le_of_lt h2⟩
  have hraw := rawOutputTotal_le_linear hM'
  have hmasked := maskedOutputTotal_le_rawOutputTotal leaves
  have htotal : maskedOutputTotal leaves ≤ leaves.length * (2 * (2 ^ 32)) :=
    Nat.le_trans hmasked hraw
  have hscaled :
      maskedOutputTotal leaves * feeDenominator ≤
        (leaves.length * (2 * (2 ^ 32))) * feeDenominator :=
    Nat.mul_le_mul_right _ htotal
  have hcapacity :
      (leaves.length * (2 * (2 ^ 32))) * feeDenominator ≤
        (64 * (2 * (2 ^ 32))) * feeDenominator := by
    exact Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ hlen)
  have hnumeric : (64 * (2 * (2 ^ 32))) * feeDenominator < goldilocks := by
    native_decide
  exact Nat.lt_of_le_of_lt (Nat.le_trans hscaled hcapacity) hnumeric

/-- The actual right-hand side uses a fee complement no larger than 10000, so
    the scaled-input bound also covers it. -/
theorem privateBatchFeeRhs_lt_modulus {leaves : List LeafPublic}
    {out : PrivateBatchOutput}
    (hlen : leaves.length ≤ 64)
    (hM : ∀ p ∈ leaves, inRange 32 p.inputAmount) :
    maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) < goldilocks := by
  have hcomp : feeDenominator - out.volumeFeeBps ≤ feeDenominator := Nat.sub_le _ _
  have hrhs :
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) ≤
        maskedInputTotal leaves * feeDenominator :=
    Nat.mul_le_mul_left _ hcomp
  exact Nat.lt_of_le_of_lt hrhs
    (maskedInputTotal_mul_feeDenominator_lt_modulus hlen hM)

/-- **Range-check side condition (i).** The fee right-hand side fits in 52 bits, so an
    honest difference `rhs − lhs ≤ rhs` passes `range_check(·, 52)`. -/
theorem privateBatchFeeRhs_lt_two_pow_52 {leaves : List LeafPublic}
    {out : PrivateBatchOutput}
    (hlen : leaves.length ≤ 64)
    (hM : ∀ p ∈ leaves, inRange 32 p.inputAmount) :
    maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) < 2 ^ 52 := by
  have hM' : ∀ p ∈ leaves, p.inputAmount ≤ 2 ^ 32 := fun p hp => Nat.le_of_lt (hM p hp)
  have htotal : maskedInputTotal leaves ≤ leaves.length * (2 ^ 32) :=
    Nat.le_trans (maskedInputTotal_le_rawInputTotal leaves) (rawInputTotal_le_linear hM')
  have hcomp : feeDenominator - out.volumeFeeBps ≤ feeDenominator := Nat.sub_le _ _
  have hscaled :
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) ≤
        (64 * (2 ^ 32)) * feeDenominator :=
    Nat.mul_le_mul (Nat.le_trans htotal (Nat.mul_le_mul_right _ hlen)) hcomp
  have hnumeric : (64 * (2 ^ 32)) * feeDenominator < 2 ^ 52 := by decide
  exact Nat.lt_of_le_of_lt hscaled hnumeric

/-- **Range-check side condition (ii).** The fee left-hand side sits more than `2^52`
    below the modulus, so a *wrapped* (dishonest, `rhs < lhs`) field difference
    `p − (lhs − rhs) ≥ p − lhs > 2^52` fails `range_check(·, 52)`. This is the bound
    the check's soundness actually rests on; `lhs < p` alone would not exclude a wrap
    landing inside the 52-bit window. -/
theorem privateBatchFeeLhs_add_two_pow_52_lt_modulus {leaves : List LeafPublic}
    (hlen : leaves.length ≤ 64)
    (hM : ∀ p ∈ leaves, inRange 32 p.outputAmount1 ∧ inRange 32 p.outputAmount2) :
    maskedOutputTotal leaves * feeDenominator + 2 ^ 52 < goldilocks := by
  have hM' : ∀ p ∈ leaves, p.outputAmount1 ≤ 2 ^ 32 ∧ p.outputAmount2 ≤ 2 ^ 32 := by
    intro p hp
    obtain ⟨h1, h2⟩ := hM p hp
    exact ⟨Nat.le_of_lt h1, Nat.le_of_lt h2⟩
  have htotal : maskedOutputTotal leaves ≤ leaves.length * (2 * (2 ^ 32)) :=
    Nat.le_trans (maskedOutputTotal_le_rawOutputTotal leaves) (rawOutputTotal_le_linear hM')
  have hscaled :
      maskedOutputTotal leaves * feeDenominator ≤ (64 * (2 * (2 ^ 32))) * feeDenominator :=
    Nat.mul_le_mul_right _ (Nat.le_trans htotal (Nat.mul_le_mul_right _ hlen))
  have hnumeric : (64 * (2 * (2 ^ 32))) * feeDenominator + 2 ^ 52 < goldilocks := by decide
  exact Nat.lt_of_le_of_lt (Nat.add_le_add_right hscaled _) hnumeric

-- ── Dummy-sentinel compatibility (leaf `blockHash = 0 ∧ outs = 0` vs private-batch
--    `blockHash = 0`) ──────────────────────────────────────────────────────────

/-- Under the leaf↔private-batch compatibility guarantee (a private-batch dummy carries zero
    outputs), the raw total coincides with the non-dummy total. Not needed for
    conservation (the in-circuit ingress mask discharges it structurally); the guarantee
    itself is discharged for valid leaves by `rawOutputTotal_eq_maskedOutputTotal_of_Rleaf`. -/
theorem rawOutputTotal_eq_maskedOutputTotal {leaves : List LeafPublic}
    (h : ∀ p ∈ leaves, isDummyPrivateBatch p → p.outputAmount1 = 0 ∧ p.outputAmount2 = 0) :
    rawOutputTotal leaves = maskedOutputTotal leaves := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      have ihrest := ih (fun q hq => h q (List.mem_cons_of_mem _ hq))
      by_cases hd : isDummyPrivateBatch p
      · obtain ⟨h1, h2⟩ := h p List.mem_cons_self hd
        simp only [rawOutputTotal, maskedOutputTotal, if_pos hd]
        rw [ihrest]; simp only [Felt] at *; omega
      · simp only [rawOutputTotal, maskedOutputTotal, if_neg hd]
        rw [ihrest]

/-- A preimage of the all-zero digest under `H`. Exhibiting one is a (first-)preimage
    break; the compatibility results below reduce to it, in the style of the
    `*_or_collision` reductions in `Security.lean`. -/
def HasZeroPreimage (H : List Felt → Digest) : Prop := ∃ x, H x = Digest.zero

/-- **Sentinel gap, reduction form.** A valid leaf that the private batch treats as a
    dummy (`blockHash = 0`) but that is *not* a leaf dummy (some output is non-zero) has
    a real block-header preimage hashing to zero — i.e. it exhibits `HasZeroPreimage`.
    So the only way the two sentinels can disagree on a valid leaf is a preimage break. -/
theorem sentinel_gap_or_zero_preimage {ro : RandomOracle} {p : LeafPublic} {w : LeafWitness}
    (h : Rleaf ro p w) (hpb : isDummyPrivateBatch p) (hleaf : ¬ p.isDummy) :
    HasZeroPreimage ro.H := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, hgated⟩ := h
  obtain ⟨-, hblock, -, -⟩ := hgated hleaf
  exact ⟨headerPreimage w p.blockNumber, hblock.symm.trans hpb⟩

/-- Under explicit zero-preimage resistance the two sentinels *coincide* on every valid
    leaf: a private-batch dummy is exactly a leaf dummy. (`←` is unconditional.) -/
theorem sentinels_agree {ro : RandomOracle} (hpre : ¬ HasZeroPreimage ro.H)
    {p : LeafPublic} {w : LeafWitness} (h : Rleaf ro p w) :
    isDummyPrivateBatch p ↔ p.isDummy := by
  constructor
  · intro hpb
    exact Classical.byContradiction fun hleaf =>
      hpre (sentinel_gap_or_zero_preimage h hpb hleaf)
  · intro hd; exact hd.1

/-- Consequently a private-batch dummy that is a valid leaf carries zero outputs — the
    hypothesis of `rawOutputTotal_eq_maskedOutputTotal`, now discharged for a batch of
    valid leaves rather than assumed. -/
theorem rawOutputTotal_eq_maskedOutputTotal_of_Rleaf {ro : RandomOracle}
    (hpre : ¬ HasZeroPreimage ro.H) {leaves : List LeafPublic}
    (hvalid : ∀ p ∈ leaves, ∃ w, Rleaf ro p w) :
    rawOutputTotal leaves = maskedOutputTotal leaves := by
  apply rawOutputTotal_eq_maskedOutputTotal
  intro p hp hpb
  obtain ⟨w, hw⟩ := hvalid p hp
  exact ((sentinels_agree hpre hw).mp hpb).2

/-- Public output of a public-batch aggregation proof (see `public_batch` constants). -/
structure PublicBatchOutput where
  aggregatorAddress : Digest
  assetId : Felt
  volumeFeeBps : Felt
  blockHash : Digest
  blockNumber : Felt
  totalExitSlots : Felt
  exitSlots : List ExitSlot
  nullifiers : List Digest

/-- Public-batch dummy sentinel: an all-dummy private batch, identified by
    `block_hash == 0` — the same shape as `isDummyPrivateBatch` one layer down.
    Such inner proofs pad partial public batches. -/
abbrev isDummyInner (o : PrivateBatchOutput) : Prop := o.blockHash = Digest.zero

/-- Boolean "is a real (non-dummy) inner", for use with `List.find?`. -/
def isRealInnerB (o : PrivateBatchOutput) : Bool := ! decide (isDummyInner o)

/-- The exit slots an inner contributes to the public output: a dummy inner's
    slots are zeroed (`select(is_dummy, 0, slot)`), a real inner's are forwarded
    verbatim. Zeroing is an enforced invariant, not a construction detail. -/
def forwardedSlots (o : PrivateBatchOutput) : List ExitSlot :=
  if isDummyInner o then o.exitSlots.map (fun _ => ⟨0, Digest.zero⟩) else o.exitSlots

/-- The nullifiers an inner contributes: a dummy inner's nullifiers are zeroed so
    its replacement nullifiers (`DNull(u)` values from the all-dummy private
    batch) never reach the chain, and one padding template can fill several
    slots without collisions. Real nullifiers are hash outputs, never zero. -/
def forwardedNullifiers (o : PrivateBatchOutput) : List Digest :=
  if isDummyInner o then o.nullifiers.map (fun _ => Digest.zero) else o.nullifiers

/-- The public-batch header comes from the first non-dummy inner (prefix scan);
    an all-dummy public batch settles to a zero block hash, which the on-chain
    verifier rejects. -/
def innerReferenceFromFirstReal (inner : List PrivateBatchOutput)
    (out : PublicBatchOutput) : Prop :=
  match inner.find? isRealInnerB with
  | some o => out.blockHash = o.blockHash ∧ out.blockNumber = o.blockNumber ∧
              out.assetId = o.assetId ∧ out.volumeFeeBps = o.volumeFeeBps
  | none   => out.blockHash = Digest.zero ∧ out.blockNumber = 0 ∧
              out.assetId = 0 ∧ out.volumeFeeBps = 0

/--
`RPublicBatch ro inner addr out` holds iff the public-batch wrapper aggregates the private-batch
outputs `inner` under aggregator address `addr`.

Higher layers operate on already-wrapped public outputs: they enforce metadata
consistency across non-dummy inners, take the header from the first non-dummy
inner, and forward exit slots / nullifiers in order (zeroing dummies'). There
is NO shuffling and NO cross-inner grouping: order-preserving forwarding keeps
each inner proof's segment attributable, which the chain's per-segment denial
relies on. Dummies here serve batch-filling, not privacy. (The implementation
builds this layer *without* zero-knowledge — `wormhole_public_batch_circuit_config` —
since its witnesses, the private-batch proofs, are themselves ZK and their public
inputs are forwarded verbatim; blinding here would cost prover time and hide
nothing. See paper §6.2.)
-/
def RPublicBatch (_ro : RandomOracle) (inner : List PrivateBatchOutput) (addr : Digest)
    (out : PublicBatchOutput) : Prop :=
  out.aggregatorAddress = addr ∧
  innerReferenceFromFirstReal inner out ∧
  (∀ o ∈ inner, ¬ isDummyInner o →
      o.assetId = out.assetId ∧
      o.volumeFeeBps = out.volumeFeeBps ∧
      o.blockHash = out.blockHash) ∧
  out.exitSlots = (inner.map forwardedSlots).flatten ∧
  out.nullifiers = (inner.map forwardedNullifiers).flatten ∧
  -- Slot-count header: `constant(n_inner · slots_per_inner)`, which is the length of
  -- the forwarded region (every inner has the shape-checked `slots_per_inner`).
  out.totalExitSlots = out.exitSlots.length
  -- NOTE: the wrapper does not constrain per-inner `blockNumber` equality; it
  -- forwards the first non-dummy inner's number. Hash equality pins the number
  -- transitively through the leaf circuit's header parse.
  -- NOTE: `aggregatorAddress` is a free witness bound only by the `= addr` conjunct;
  -- what the chain does with it (fee-recipient derivation) is a pallet-side semantics,
  -- not a circuit constraint, and is out of scope here.

/-- Forwarding preserves each inner's slot count (zeroing is a `map`). -/
theorem forwardedSlots_length (o : PrivateBatchOutput) :
    (forwardedSlots o).length = o.exitSlots.length := by
  unfold forwardedSlots
  split <;> simp

/-- The public-batch exit region is the concatenation of the inners' regions, so its
    length — the `totalExitSlots` header — is the sum of the inner slot counts. -/
theorem RPublicBatch_totalExitSlots {ro : RandomOracle} {inner : List PrivateBatchOutput}
    {addr : Digest} {out : PublicBatchOutput} (h : RPublicBatch ro inner addr out) :
    out.totalExitSlots = (inner.map fun o => o.exitSlots.length).sum := by
  rw [h.2.2.2.2.2, h.2.2.2.1, List.length_flatten, List.map_map]
  congr 1
  apply List.map_congr_left
  intro o _
  exact forwardedSlots_length o

end WormholeSpec
