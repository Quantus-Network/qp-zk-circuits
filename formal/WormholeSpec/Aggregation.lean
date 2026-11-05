/-
  Private-batch and public-batch aggregation relations.

  These capture the wrapper constraints in `build_private_batch_constraints` and
  `build_public_batch_constraints`:

    * metadata consistency across non-dummy children (asset_id, block hash);
    * the block reference being taken from the first non-dummy slot (the
      position-independent selection from the `illuzen/full-shuffle` fix), with
      an all-dummy batch settling to a zero block hash;
    * `M` prover-chosen exit slots `(amount, account)` and the batch fee rate,
      exposed verbatim as public outputs (each amount 32-bit range-checked);
    * one fee inequality over the dummy-masked input total of the whole private
      segment and the exit-slot total:
      `sum(amounts) · 10000 ≤ sum(real inputs) · (10000 − fee_bps)`;
    * dummy-nullifier replacement `DNull(u) = H(H(u))`;
    * the nullifier region emitted as a privately witnessed permutation of the
      per-slot selections: every selected digest is preserved exactly, while
      its public output position need not match its producing leaf slot;
    * pairwise distinctness of the *real* slots' nullifiers
      (`realNullifiersDistinct`): the anti-replay constraint. One leaf proof
      replayed into `k` slots would count its burn `k` times in the fee sum
      against a single on-chain nullifier; the circuit makes such a batch
      unprovable, and `RPrivateBatch_settles_distinct_spends` is the theorem
      that constraint exists for;
    * the slot-count header `numExitSlots = M` (a circuit constant equal to the
      length of the exit region).

  Leaves are proofs of burn (`Rleaf`): they carry no outputs and no fee. Exits
  are therefore not derived from children at all; they are free witnesses bound
  only by `privateBatchFeeOk`. That is what lets one burn fund many exits and
  many burns fund one exit. Economic conservation is the segment-level
  predicate `privateBatchFeeOk`; `RPrivateBatch_settlement_le_input` is its
  unscaled corollary.

  The dummy sentinel is the same at both layers (`block_hash == 0`;
  `LeafPublic.isDummy` and `isDummyPrivateBatch` are definitionally equal), and
  `Rleaf` forces a dummy's `inputAmount` to zero, so the wrapper's input mask is
  defense in depth rather than a correctness requirement.

  AGGREGATE FEES OVER `Nat` VS `ZMod p` (a Phase-2 caveat)
  --------------------------------------------------------
  The fee comparison is a `Nat` inequality, while the circuit computes both
  scaled sides and their difference in the Goldilocks field. Merely proving the
  unscaled totals `< goldilocks` is therefore insufficient: both
  `slotsTotal · 10000` and `maskedInputTotal · (10000 − fee_bps)` must not wrap.

  The bounds below make that obligation explicit. They first bound raw and
  masked totals linearly, then prove the two scaled sides are below
  `goldilocks` for at most 64 children / 64 exit slots with 32-bit amounts.

  The circuit enforces the inequality as `range_check(rhs − lhs, 52)` over the
  field. That check is sound by a *two-sided* argument, and `lhs < p` alone is
  not enough for it: (i) an honest `rhs ≥ lhs` gives `rhs − lhs ≤ rhs < 2^52`
  (`privateBatchFeeRhs_lt_two_pow_52`); (ii) a dishonest `rhs < lhs` wraps to
  `p − (lhs − rhs) ≥ p − lhs`, which must land *above* `2^52`, i.e. `lhs < p − 2^52`
  (`privateBatchFeeLhs_add_two_pow_52_lt_modulus`). The field-level lift of these
  two bounds through the range-check gadget is the `Plonky2Spec` obligation; the
  `Nat` bounds here are its side conditions.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf

namespace WormholeSpec

/-- One exit slot: an amount and its destination account. -/
structure ExitSlot where
  amount : Felt
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

/-- Private-batch dummy sentinel: `block_hash == 0`, the same as the leaf's
    `LeafPublic.isDummy`. `abbrev` (reducible) so `Decidable` resolves through it via
    `DecidableEq Digest`. -/
abbrev isDummyPrivateBatch (p : LeafPublic) : Prop := p.blockHash = Digest.zero

/-- Boolean "is a real (non-dummy) child", for use with `List.find?`. -/
def isRealB (p : LeafPublic) : Bool := ! decide (isDummyPrivateBatch p)

/-- Total input amount over every child, dummies included. Used to bound the
    dummy-masked input accumulator. -/
def rawInputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest => p.inputAmount + rawInputTotal rest

/-- Input total restricted to real children, exactly matching the private-batch
    circuit's dummy-masked input accumulator. -/
def maskedInputTotal : List LeafPublic → Felt
  | [] => 0
  | p :: rest =>
      (if isDummyPrivateBatch p then 0 else p.inputAmount) + maskedInputTotal rest

/-- Sum of the exit-slot amounts (the value leaving the batch). -/
def slotsTotal : List ExitSlot → Felt
  | [] => 0
  | s :: rest => s.amount + slotsTotal rest

/-- Sum of the exit-slot amounts of a private-batch output. -/
def outputExitTotal (out : PrivateBatchOutput) : Felt := slotsTotal out.exitSlots

/-- Basis-point denominator used by the private-batch fee constraint. -/
def feeDenominator : Felt := 10000

/-- One fee/value-conservation check for an entire private segment. Dummy child
    inputs do not contribute. The bound on `volumeFeeBps` makes the `Nat`
    subtraction agree with the intended nonnegative field complement; the
    circuit enforces it with `range_check(fee_bps, 14)` together with
    `range_check(10000 − fee_bps, 14)`, since the fee is a free witness. -/
def privateBatchFeeOk (leaves : List LeafPublic) (out : PrivateBatchOutput) : Prop :=
  out.volumeFeeBps ≤ feeDenominator ∧
  outputExitTotal out * feeDenominator ≤
    maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps)

/-- Metadata of each non-dummy child agrees with the aggregate header: asset id
    (`connect`) and block hash (`or(is_dummy, matches_ref) = 1`). The circuit does
    *not* constrain the children's `blockNumber`; it forwards the first real child's
    (`referenceFromFirstReal`), and the chain only reads that one, to look up the hash it
    checks `out.blockHash` against. Equal hashes pin the number through the leaf circuit's
    header parse (`Rleaf`: `blockHash = H (headerPreimage w blockNumber)`), so a real child
    with the header's hash and a different number is a collision. Same shape as
    `RPublicBatch` one layer up. -/
def metadataConsistent (leaves : List LeafPublic) (out : PrivateBatchOutput) : Prop :=
  ∀ p ∈ leaves, ¬ isDummyPrivateBatch p →
    p.assetId = out.assetId ∧
    p.blockHash = out.blockHash

/-- The block reference is the first non-dummy child; an all-dummy batch keeps the
    scan's zero initial values for the block hash and number (and settles nothing).
    `assetId` is taken from slot 0 unconditionally (every slot's asset is connected to
    it, dummies included), so it is not part of the scan. The fee rate is a batch
    witness, not a child field, and is not part of the scan either. -/
def referenceFromFirstReal (leaves : List LeafPublic) (out : PrivateBatchOutput) : Prop :=
  match leaves.find? isRealB with
  | some p => out.blockHash = p.blockHash ∧ out.blockNumber = p.blockNumber ∧
              out.assetId = p.assetId
  | none   => out.blockHash = Digest.zero ∧ out.blockNumber = 0

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
`Vec<[Target; 4]>` allocated once *per leaf slot*, not once per dummy. The wrapper
reads slot `i`'s preimage only when slot `i` is a dummy (`select(is_dummy_i, …)`).

NULLIFIER ORDERING. The circuit routes the per-slot selections through private
boolean switches before registering them. The public output is therefore any
permutation chosen by the local prover, while the `Perm` relation proves exact
multiset preservation. The permutation witness is not part of the public
output.

The exit slots and the fee rate are the prover's witnesses (`exit_slots`,
`volume_fee_bps` in `PrivateBatchCircuitTargets`); the relation constrains them only
through the 32-bit amount range checks and `privateBatchFeeOk`.
-/
def RPrivateBatch (ro : RandomOracle) (leaves : List LeafPublic) (us : List (List Felt))
    (out : PrivateBatchOutput) : Prop :=
  metadataConsistent leaves out ∧
  referenceFromFirstReal leaves out ∧
  (∃ raw, nullifiersReplaced ro leaves us raw ∧ out.nullifiers.Perm raw) ∧
  out.nullifiers.length = leaves.length ∧
  -- Each exit amount is a 32-bit witness (`range_check(slot.amount, 32)`).
  (∀ s ∈ out.exitSlots, inRange 32 s.amount) ∧
  privateBatchFeeOk leaves out ∧
  -- Anti-replay: real slots spend pairwise-distinct nullifiers.
  realNullifiersDistinct leaves ∧
  -- Slot-count header (`num_exit_slots_t = constant(num_exit_slots)`).
  out.numExitSlots = out.exitSlots.length

-- ── Slot accounting ─────────────────────────────────────────────────────────

/-- The `numExitSlots` header the circuit emits as a constant is the length of the
    exit region it describes. -/
theorem RPrivateBatch_exitSlots_length {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    out.exitSlots.length = out.numExitSlots :=
  h.2.2.2.2.2.2.2.symm

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
    ∀ (leaves : List LeafPublic) (us : List (List Felt)) (ns : List Digest),
      nullifiersReplaced ro leaves us ns →
      ∀ p ∈ leaves, ¬ isDummyPrivateBatch p → p.nullifier ∈ ns
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

/-- The masked input total is the raw input total of the real children alone. -/
theorem maskedInputTotal_eq_rawInputTotal_realLeaves (leaves : List LeafPublic) :
    maskedInputTotal leaves = rawInputTotal (realLeaves leaves) := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      by_cases hd : isDummyPrivateBatch p
      · have hf : isRealB p = false := isRealB_false_iff.mpr hd
        have e1 : maskedInputTotal (p :: rest) = 0 + maskedInputTotal rest := by
          simp only [maskedInputTotal, if_pos hd]
        have e2 : realLeaves (p :: rest) = realLeaves rest := by
          simp only [realLeaves, List.filter_cons, hf, Bool.false_eq_true, if_false]
        rw [e1, e2, ih, Nat.zero_add]
      · have ht : isRealB p = true := isRealB_true_iff.mpr hd
        have e1 : maskedInputTotal (p :: rest) = p.inputAmount + maskedInputTotal rest := by
          simp only [maskedInputTotal, if_neg hd]
        have e2 : realLeaves (p :: rest) = p :: realLeaves rest := by
          simp only [realLeaves, List.filter_cons, ht, if_true]
        rw [e1, e2, rawInputTotal, ih]

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

-- ── Aggregate-fee consequences and no-wraparound bounds ─────────────────────

/-- The primitive relation exposes the private-segment fee inequality. -/
theorem RPrivateBatch_fee_conservation {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out * feeDenominator ≤
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) :=
  h.2.2.2.2.2.1.2

/-- A valid private segment has a well-formed basis-point rate. -/
theorem RPrivateBatch_fee_bps_bound {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    out.volumeFeeBps ≤ feeDenominator :=
  h.2.2.2.2.2.1.1

/-- Aggregate fee conservation implies that the settled exits cannot exceed the
    real inputs, independently of how value is pooled among leaves. -/
theorem privateBatchFeeOk_output_le_input {leaves : List LeafPublic}
    {out : PrivateBatchOutput} (h : privateBatchFeeOk leaves out) :
    outputExitTotal out ≤ maskedInputTotal leaves := by
  have hcomp : feeDenominator - out.volumeFeeBps ≤ feeDenominator := Nat.sub_le _ _
  have hrhs :
      maskedInputTotal leaves * (feeDenominator - out.volumeFeeBps) ≤
        maskedInputTotal leaves * feeDenominator :=
    Nat.mul_le_mul_left _ hcomp
  have hscaled := Nat.le_trans h.2 hrhs
  exact Nat.le_of_mul_le_mul_right hscaled (by unfold feeDenominator; omega)

/-- The amount actually settled by a private segment cannot exceed that segment's
    total real input. -/
theorem RPrivateBatch_settlement_le_input {ro : RandomOracle}
    {leaves : List LeafPublic} {us : List (List Felt)} {out : PrivateBatchOutput}
    (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out ≤ maskedInputTotal leaves :=
  privateBatchFeeOk_output_le_input h.2.2.2.2.2.1

/-- **One spend per settled leaf.** The value a private batch settles is covered by the
    burns of its real children, and those children spend pairwise-distinct nullifiers — so
    no leaf proof is counted twice against a single on-chain nullifier. This is the
    property the uniqueness constraint was added to protect (the replay-inflation
    finding). -/
theorem RPrivateBatch_settles_distinct_spends {ro : RandomOracle} {leaves : List LeafPublic}
    {us : List (List Felt)} {out : PrivateBatchOutput} (h : RPrivateBatch ro leaves us out) :
    outputExitTotal out ≤ rawInputTotal (realLeaves leaves) ∧ (realNullifiers leaves).Nodup :=
  ⟨(maskedInputTotal_eq_rawInputTotal_realLeaves leaves) ▸ RPrivateBatch_settlement_le_input h,
    realNullifiersDistinct_nodup h.2.2.2.2.2.2.1⟩

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

/-- A per-slot bound `M` lifts to a linear bound on the exit total. -/
theorem slotsTotal_le_linear {slots : List ExitSlot} {M : Felt}
    (h : ∀ s ∈ slots, s.amount ≤ M) :
    slotsTotal slots ≤ slots.length * M := by
  induction slots with
  | nil => simp [slotsTotal]
  | cons s rest ih =>
      have hs := h s List.mem_cons_self
      have ihrest := ih (fun q hq => h q (List.mem_cons_of_mem _ hq))
      have hexp : (rest.length + 1) * M = rest.length * M + M := Nat.succ_mul _ _
      simp only [slotsTotal, List.length_cons, Felt] at *
      omega

/-- The explicit unscaled input no-wraparound bound for the Phase-2 field model. -/
theorem rawInputTotal_lt_modulus {leaves : List LeafPublic} {M : Felt}
    (hM : ∀ p ∈ leaves, p.inputAmount ≤ M)
    (hbatch : leaves.length * M < goldilocks) :
    rawInputTotal leaves < goldilocks :=
  Nat.lt_of_le_of_lt (rawInputTotal_le_linear hM) hbatch

/-- Unscaled no-wraparound for the masked input accumulator. -/
theorem maskedInputTotal_lt_modulus {leaves : List LeafPublic} {M : Felt}
    (hM : ∀ p ∈ leaves, p.inputAmount ≤ M)
    (hbatch : leaves.length * M < goldilocks) :
    maskedInputTotal leaves < goldilocks :=
  Nat.lt_of_le_of_lt (maskedInputTotal_le_rawInputTotal leaves)
    (rawInputTotal_lt_modulus hM hbatch)

/-- Unscaled no-wraparound for the exit-slot accumulator. -/
theorem slotsTotal_lt_modulus {slots : List ExitSlot} {M : Felt}
    (hM : ∀ s ∈ slots, s.amount ≤ M)
    (hbatch : slots.length * M < goldilocks) :
    slotsTotal slots < goldilocks :=
  Nat.lt_of_le_of_lt (slotsTotal_le_linear hM) hbatch

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

/-- For the protocol maximum of 64 exit slots and 32-bit amounts, the scaled
    aggregate output side cannot wrap in the Goldilocks field. -/
theorem slotsTotal_mul_feeDenominator_lt_modulus {slots : List ExitSlot}
    (hlen : slots.length ≤ 64)
    (hM : ∀ s ∈ slots, inRange 32 s.amount) :
    slotsTotal slots * feeDenominator < goldilocks := by
  have hM' : ∀ s ∈ slots, s.amount ≤ 2 ^ 32 := fun s hs => Nat.le_of_lt (hM s hs)
  have htotal : slotsTotal slots ≤ slots.length * (2 ^ 32) := slotsTotal_le_linear hM'
  have hscaled :
      slotsTotal slots * feeDenominator ≤ (slots.length * (2 ^ 32)) * feeDenominator :=
    Nat.mul_le_mul_right _ htotal
  have hcapacity :
      (slots.length * (2 ^ 32)) * feeDenominator ≤ (64 * (2 ^ 32)) * feeDenominator := by
    exact Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ hlen)
  have hnumeric : (64 * (2 ^ 32)) * feeDenominator < goldilocks := by
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
theorem privateBatchFeeLhs_add_two_pow_52_lt_modulus {out : PrivateBatchOutput}
    (hlen : out.exitSlots.length ≤ 64)
    (hM : ∀ s ∈ out.exitSlots, inRange 32 s.amount) :
    outputExitTotal out * feeDenominator + 2 ^ 52 < goldilocks := by
  have hM' : ∀ s ∈ out.exitSlots, s.amount ≤ 2 ^ 32 := fun s hs => Nat.le_of_lt (hM s hs)
  have htotal : slotsTotal out.exitSlots ≤ out.exitSlots.length * (2 ^ 32) :=
    slotsTotal_le_linear hM'
  have hscaled :
      slotsTotal out.exitSlots * feeDenominator ≤ (64 * (2 ^ 32)) * feeDenominator :=
    Nat.mul_le_mul_right _ (Nat.le_trans htotal (Nat.mul_le_mul_right _ hlen))
  have hnumeric : (64 * (2 ^ 32)) * feeDenominator + 2 ^ 52 < goldilocks := by decide
  unfold outputExitTotal
  exact Nat.lt_of_le_of_lt (Nat.add_le_add_right hscaled _) hnumeric

-- ── Dummy-sentinel compatibility ─────────────────────────────────────────────

/-- The leaf and private-batch dummy notions coincide (both are `blockHash = 0`). -/
theorem sentinels_agree (p : LeafPublic) : isDummyPrivateBatch p ↔ p.isDummy := Iff.rfl

/-- A valid leaf that the private batch treats as a dummy burns nothing, so the
    wrapper's input mask (`select(is_dummy, 0, input)`) is defense in depth: on valid
    leaves the masked and raw input totals agree. -/
theorem rawInputTotal_eq_maskedInputTotal_of_Rleaf {ro : RandomOracle} {leaves : List LeafPublic}
    (hvalid : ∀ p ∈ leaves, ∃ w, Rleaf ro p w) :
    rawInputTotal leaves = maskedInputTotal leaves := by
  induction leaves with
  | nil => rfl
  | cons p rest ih =>
      have ihrest := ih (fun q hq => hvalid q (List.mem_cons_of_mem _ hq))
      by_cases hd : isDummyPrivateBatch p
      · obtain ⟨w, hw⟩ := hvalid p List.mem_cons_self
        obtain ⟨-, -, -, -, -, -, -, -, -, hzero, -⟩ := hw
        have h0 : p.inputAmount = 0 := hzero hd
        simp only [rawInputTotal, maskedInputTotal, if_pos hd, h0]
        rw [ihrest]
      · simp only [rawInputTotal, maskedInputTotal, if_neg hd]
        rw [ihrest]

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
  -- Each inner's slot-count header is `connect`ed to the configured `slots_per_inner`,
  -- the length of its exit region. The inner PI length alone does not identify the
  -- shape (`(N=1, M=5)` and `(N=6, M=1)` are both 37 felts), so without this binding a
  -- same-length inner of another shape would have its exits forwarded as nullifiers.
  (∀ o ∈ inner, o.numExitSlots = o.exitSlots.length) ∧
  -- Slot-count header: `constant(n_inner · slots_per_inner)`, which is the length of
  -- the forwarded region.
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
  rw [h.2.2.2.2.2.2, h.2.2.2.1, List.length_flatten, List.map_map]
  congr 1
  apply List.map_congr_left
  intro o _
  exact forwardedSlots_length o

end WormholeSpec
