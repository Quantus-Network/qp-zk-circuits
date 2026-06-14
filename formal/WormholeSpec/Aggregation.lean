/-
  Layer-0 and layer-1 aggregation relations.

  These capture the wrapper constraints in `build_layer0_wrapper_constraints` and
  `build_layer1_wrapper_constraints`:

    * metadata consistency across non-dummy children (asset_id, fee, block);
    * the block reference being taken from the first non-dummy slot (the
      position-independent selection from the `illuzen/full-shuffle` fix), with
      an all-dummy batch settling to a zero block hash;
    * dummy-nullifier replacement `DNull(u) = H(H(u))`;
    * value conservation of the exit totals.

  NOTE the *weaker* layer-0 dummy sentinel: at layer 0 a child is treated as a
  dummy when `block_hash == 0` alone (`isDummyL0`), versus the leaf circuit's
  `block_hash == 0 ∧ outputs == 0`. The two notions and their compatibility are
  exactly the kind of obligation Phase 3 must discharge.

  Exit *grouping/dedup* (merging equal exit accounts into one first-occurrence
  slot) is abstracted here to total conservation; refining it to the full
  multiset relation is a Phase-3 task (marked TODO).
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

/-- Boolean "is a real (non-dummy) child", for use with `List.find?`/`filter`. -/
def isRealB (p : LeafPublic) : Bool := ! decide (isDummyL0 p)

/-- Sum of output amounts over the non-dummy children (the value entering the batch). -/
def inputExitTotal (leaves : List LeafPublic) : Nat :=
  (leaves.map (fun p => if isDummyL0 p then 0 else p.outputAmount1 + p.outputAmount2)).sum

/-- Sum of the settled exit-slot amounts (the value leaving the batch). -/
def outputExitTotal (out : Layer0Output) : Nat :=
  (out.exitSlots.map (fun e => e.sum)).sum

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

`us` has one entry per child (used only on dummy slots).
-/
def RL0 (ro : RandomOracle) (leaves : List LeafPublic) (us : List (List Felt))
    (out : Layer0Output) : Prop :=
  metadataConsistent leaves out ∧
  referenceFromFirstReal leaves out ∧
  nullifiersReplaced ro leaves us out.nullifiers ∧
  out.nullifiers.length = leaves.length ∧
  -- Value conservation of exits.
  outputExitTotal out = inputExitTotal leaves
  -- TODO(Phase 3): full exit grouping/dedup as a multiset relation between the
  -- children's (account, amount) outputs and `out.exitSlots`, plus the
  -- `numExitSlots = 2 * leaves.length` slot accounting.

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
