/-
  Layer-0 and layer-1 aggregation relations.

  These capture the wrapper constraints in `build_layer0_wrapper_constraints` and
  `build_layer1_wrapper_constraints`:

    * metadata consistency across non-dummy children (asset_id, fee, block);
    * the block reference being taken from the first non-dummy slot (the
      position-independent selection from the `illuzen/full-shuffle` fix), with
      an all-dummy batch settling to a zero block hash;
    * dummy-nullifier replacement `DNull(u) = H(H(u))`;
    * the exit *grouping/dedup* primitive (`groupExits`) that builds the `2N`
      settled slots.

  Value conservation is no longer asserted: `R_L0` now pins the exact in-circuit
  grouping, and conservation (`outputExitTotal = rawOutputTotal`) is *derived* as
  a theorem (`RL0_value_conservation`).

  NOTE the *weaker* layer-0 dummy sentinel: at layer 0 a child is treated as a
  dummy when `block_hash == 0` alone (`isDummyL0`), versus the leaf circuit's
  `block_hash == 0 ∧ outputs == 0`. Their compatibility (dummy ⟹ zero outputs) is
  the hypothesis of `rawOutputTotal_eq_inputExitTotal`, the obligation a full
  leaf↔layer-0 composition proof must discharge.

  CONSERVATION OVER `Nat` VS `ZMod p` (a Phase-2 caveat)
  ------------------------------------------------------
  `RL0_value_conservation` is an *exact* `Nat` identity, so it is economically
  meaningful as stated. The in-circuit accumulators, however, live in the field:
  over `ZMod goldilocks` (Phase 2) "conservation" would only be equality *mod p*,
  and two distinct totals could be congruent. The result stays meaningful exactly
  while the total cannot wrap — i.e. under the explicit hypothesis
  `rawOutputTotal leaves < goldilocks`. That bound is *not* hand-waved: it is
  discharged below (`rawOutputTotal_lt_modulus`) from the leaf circuit's 32-bit
  output range checks plus a batch-size bound, with an enormous margin
  (`n · 2³³ < p` holds for any `n < 2³¹`, versus realistic batches of a few
  dozen). Phase 2 must (a) carry `rawOutputTotal leaves < goldilocks` as a
  hypothesis on the field-level conservation statement, and (b) rework the
  `omega`-based proofs here, since `omega` reasons over `Nat`/`Int` and does not
  apply to `ZMod p` arithmetic.
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

/-- Public output of a layer-0 aggregation proof (see `aggregated_output`). -/
structure Layer0Output where
  numExitSlots : Felt
  assetId : Felt
  volumeFeeBps : Felt
  blockHash : Digest
  blockNumber : Felt
  exitSlots : List ExitSlot
  nullifiers : List Digest

/-- Layer-0 dummy sentinel: `block_hash == 0` (weaker than the leaf's notion).
    `abbrev` (reducible) so `Decidable` resolves through it via `DecidableEq Digest`. -/
abbrev isDummyL0 (p : LeafPublic) : Prop := p.blockHash = Digest.zero

/-- Boolean "is a real (non-dummy) child", for use with `List.find?`. -/
def isRealB (p : LeafPublic) : Bool := ! decide (isDummyL0 p)

/-- Total of the two output amounts over *every* child. This is exactly what the
    in-circuit exit accumulator sums — it does not gate on the dummy flag. -/
def rawOutputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest => (p.outputAmount1 + p.outputAmount2) + rawOutputTotal rest

/-- Output total restricted to non-dummy children (the value entering the batch,
    once the leaf guarantee "dummy ⟹ zero outputs" is taken into account). -/
def inputExitTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest =>
      (if isDummyL0 p then 0 else p.outputAmount1 + p.outputAmount2) + inputExitTotal rest

/-- The flattened `(account, amount)` outputs of all children, two per child.
    These are the `2N` slot inputs to the grouping in
    `build_layer0_wrapper_constraints`. -/
def childPairs : List LeafPublic → List (Digest × Felt)
  | [] => []
  | p :: rest =>
      (p.exitAccount1, p.outputAmount1) ::
      (p.exitAccount2, p.outputAmount2) :: childPairs rest

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

/-- Sum of the settled exit-slot amounts of a layer-0 output. -/
def outputExitTotal (out : Layer0Output) : Felt := slotsTotal out.exitSlots

/-- Metadata of each non-dummy child agrees with the aggregate header. -/
def metadataConsistent (leaves : List LeafPublic) (out : Layer0Output) : Prop :=
  ∀ p ∈ leaves, ¬ isDummyL0 p →
    p.assetId = out.assetId ∧
    p.volumeFeeBps = out.volumeFeeBps ∧
    p.blockHash = out.blockHash ∧
    p.blockNumber = out.blockNumber

/-- The block reference is the first non-dummy child; an all-dummy batch yields a
    zero block hash (and settles nothing). -/
def referenceFromFirstReal (leaves : List LeafPublic) (out : Layer0Output) : Prop :=
  match leaves.find? isRealB with
  | some p => out.blockHash = p.blockHash ∧ out.blockNumber = p.blockNumber ∧
              out.assetId = p.assetId ∧ out.volumeFeeBps = p.volumeFeeBps
  | none   => out.blockHash = Digest.zero

/-- Per-slot nullifier output: real children forward `nullifier`; layer-0 dummies
    are replaced by `DNull(u)` for the witnessed preimage `u`. -/
def nullifiersReplaced (ro : RandomOracle) :
    List LeafPublic → List (List Felt) → List Digest → Prop
  | [],      [],      []      => True
  | p :: ps, u :: us, n :: ns =>
      (n = if isDummyL0 p then ro.dummyNull u else p.nullifier) ∧
      nullifiersReplaced ro ps us ns
  | _,       _,       _       => False

/--
`RL0 ro leaves us out` holds iff the layer-0 wrapper accepts children `leaves`
with dummy-nullifier preimages `us`, producing aggregate output `out`.

`us` has one entry per child (used only on dummy slots). This matches the circuit
witness layout exactly: `AggregationCircuitTargets.dummy_nullifier_pre_images` is a
`Vec<[Target; 4]>` allocated once *per leaf slot* (`for _ in 0..n_leaf`), not once
per dummy — see `layer0/circuit/circuit_logic.rs:46–47, 76–85`. The wrapper reads
slot `i`'s preimage only when slot `i` is a dummy (`select(is_dummy_i, …)`), so the
per-child length bookkeeping here (`out.nullifiers.length = leaves.length`) lines up
with the circuit.
-/
def RL0 (ro : RandomOracle) (leaves : List LeafPublic) (us : List (List Felt))
    (out : Layer0Output) : Prop :=
  metadataConsistent leaves out ∧
  referenceFromFirstReal leaves out ∧
  nullifiersReplaced ro leaves us out.nullifiers ∧
  out.nullifiers.length = leaves.length ∧
  -- Primitive exit construction: the settled slots are *exactly* the in-circuit
  -- group/dedup of every child's two (account, amount) outputs. Value
  -- conservation is a derived theorem (`RL0_value_conservation`), not an
  -- assumed conjunct.
  out.exitSlots = groupExits (childPairs leaves)
  -- TODO(Phase 3): `numExitSlots = 2 * leaves.length` slot accounting.

-- ── Value conservation, derived from the grouping primitive ─────────────────

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

/-- `amtNotIn []` over the children's pairs is the raw output total. -/
theorem amtNotIn_nil_childPairs (leaves : List LeafPublic) :
    amtNotIn [] (childPairs leaves) = rawOutputTotal leaves := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      show p.outputAmount1 + (p.outputAmount2 + amtNotIn [] (childPairs rest))
          = (p.outputAmount1 + p.outputAmount2) + rawOutputTotal rest
      rw [ih]; simp only [Felt] at *; omega

/-- Conservation for the top-level grouping of the children's outputs. -/
theorem groupExits_childPairs (leaves : List LeafPublic) :
    slotsTotal (groupExits (childPairs leaves)) = rawOutputTotal leaves := by
  unfold groupExits
  rw [groupAux_conserves [] (childPairs leaves), amtNotIn_nil_childPairs]

/-- **Value conservation** (whitepaper §6.1): every layer-0 proof settles exactly
    the value its children carry. Derived from the grouping primitive in `RL0`. -/
theorem RL0_value_conservation {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : Layer0Output} (h : RL0 ro leaves us out) :
    outputExitTotal out = rawOutputTotal leaves := by
  unfold outputExitTotal
  rw [h.2.2.2.2]
  exact groupExits_childPairs leaves

-- ── No-wraparound bound (makes the Phase-2 field hypothesis explicit) ────────

/-- A per-output bound `M` lifts to a linear bound on the batch total: with each
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

/-- The explicit *no-wraparound* bound that the field model (Phase 2) must assume.
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

/-- Under the leaf↔layer-0 compatibility guarantee (a layer-0 dummy carries zero
    outputs), the raw total coincides with the non-dummy total. -/
theorem rawOutputTotal_eq_inputExitTotal {leaves : List LeafPublic}
    (h : ∀ p ∈ leaves, isDummyL0 p → p.outputAmount1 = 0 ∧ p.outputAmount2 = 0) :
    rawOutputTotal leaves = inputExitTotal leaves := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      have ihrest := ih (fun q hq => h q (List.mem_cons_of_mem _ hq))
      by_cases hd : isDummyL0 p
      · obtain ⟨h1, h2⟩ := h p List.mem_cons_self hd
        simp only [rawOutputTotal, inputExitTotal, if_pos hd]
        rw [ihrest]; simp only [Felt] at *; omega
      · simp only [rawOutputTotal, inputExitTotal, if_neg hd]
        rw [ihrest]

/-- Public output of a layer-1 aggregation proof (see `layer1` constants). -/
structure Layer1Output where
  aggregatorAddress : Digest
  assetId : Felt
  volumeFeeBps : Felt
  blockHash : Digest
  blockNumber : Felt
  totalExitSlots : Felt
  exitSlots : List ExitSlot
  nullifiers : List Digest

/--
`RL1 ro inner addr out` holds iff the layer-1 wrapper aggregates the layer-0
outputs `inner` under aggregator address `addr`.

Higher layers operate on already-wrapped public outputs: they enforce metadata
consistency and forward exit slots / nullifiers in order. (The implementation
currently keeps these layers zero-knowledge as well; that is a perf choice, not
a soundness requirement — see paper §6.2.)
-/
def RL1 (_ro : RandomOracle) (inner : List Layer0Output) (addr : Digest)
    (out : Layer1Output) : Prop :=
  out.aggregatorAddress = addr ∧
  (∀ o ∈ inner,
      o.assetId = out.assetId ∧
      o.volumeFeeBps = out.volumeFeeBps ∧
      o.blockHash = out.blockHash ∧
      o.blockNumber = out.blockNumber) ∧
  out.exitSlots = (inner.map (fun o => o.exitSlots)).flatten ∧
  out.nullifiers = (inner.map (fun o => o.nullifiers)).flatten
  -- TODO(Phase 3): `totalExitSlots` accounting and the layer-1 aggregator-address
  -- binding semantics.

end WormholeSpec
