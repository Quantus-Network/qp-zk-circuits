/-
  The leaf relation R_leaf (paper §3.3, constraints C1–C5).

  STRUCTURE
  ---------
  The Rust circuit applies most constraints unconditionally and gates only three
  on `is_not_dummy` (see `connect_shared_targets`):

    * C1 nullifier hash,
    * C4 block-hash preimage,
    * the ZK-tree root binding `header.zk_tree_root == merkle_root`.

  Everything else (range checks, C5 fee inequality, C2 wormhole-address
  derivation, the leaf-hash computation, the Merkle walk, and the shared-target
  equalities) holds for dummy and non-dummy proofs alike. `R_leaf` mirrors that
  split exactly. Shared-target equalities (`nullifier.secret == account.secret`,
  `transfer_count` agreement, `to_account == account_id`) are encoded structurally
  by reusing the same witness fields rather than as separate clauses.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash

namespace WormholeSpec

/-- One level of the 4-ary Merkle authentication path: a position hint in `{0,1,2,3}`
    and the three sibling digests in sorted order. -/
structure MerkleLevel where
  pos : Felt
  s0 : Digest
  s1 : Digest
  s2 : Digest
  deriving Repr

/-- The 21-felt public input vector of a leaf proof (see `qp-wormhole-inputs`).
    `exitAccount1/2` are public but *unconstrained* at the leaf — they are bound
    only by the layer-0 aggregator — so they deliberately appear here yet are
    referenced by no clause of `R_leaf`. -/
structure LeafPublic where
  assetId : Felt
  outputAmount1 : Felt
  outputAmount2 : Felt
  volumeFeeBps : Felt
  nullifier : Digest
  exitAccount1 : Digest
  exitAccount2 : Digest
  blockHash : Digest
  blockNumber : Felt
  deriving Repr

/-- The private witness of a leaf proof. -/
structure LeafWitness where
  secret : Digest
  /-- Transfer count `c`, 2 felts (`FELTS_PER_U64`). -/
  transferCount : List Felt
  inputAmount : Felt
  /-- The funding account; bound to `WA(secret)` by C2 and to the Merkle leaf. -/
  toAccount : Digest
  -- Block-header private fields (preimage of `block_hash`).
  parentHash : Digest
  stateRoot : Digest
  extrinsicsRoot : Digest
  zkTreeRoot : Digest
  digestLogs : List Felt
  -- ZK-tree authentication path.
  depth : Nat
  levels : List MerkleLevel
  rootHash : Digest

/-- Maximum ZK-tree depth (`MAX_DEPTH`). -/
def maxDepth : Nat := 16

/-- `is_dummy` at the *leaf*: `block_hash == 0` AND both outputs `== 0`. -/
def LeafPublic.isDummy (p : LeafPublic) : Prop :=
  p.blockHash = Digest.zero ∧ p.outputAmount1 = 0 ∧ p.outputAmount2 = 0

/-- C5 — fee / value conservation:
    `(out₁ + out₂) · 10000 ≤ input · (10000 − fee_bps)`. The `fee_bps ≤ 10000`
    side condition (range-checked to 14 bits in-circuit) keeps the truncated `Nat`
    subtraction faithful to the field arithmetic. -/
def feeOk (p : LeafPublic) (w : LeafWitness) : Prop :=
  (p.outputAmount1 + p.outputAmount2) * 10000 ≤ w.inputAmount * (10000 - p.volumeFeeBps)

/-- C4 — block-header preimage, order per `HeaderTargets::collect_to_vec`:
    `parent_hash ‖ block_number ‖ state_root ‖ extrinsics_root ‖ zk_tree_root ‖ digest`. -/
def headerPreimage (w : LeafWitness) (blockNumber : Felt) : List Felt :=
  w.parentHash.toList ++ [blockNumber] ++ w.stateRoot.toList ++
    w.extrinsicsRoot.toList ++ w.zkTreeRoot.toList ++ w.digestLogs

/-- One upward step of the Merkle walk: insert `cur` at `lvl.pos` among the three
    sorted siblings, then hash the 4 children. Matches the position `select` logic
    in `ZkMerkleProofData::circuit`. -/
def stepUp (ro : RandomOracle) (cur : Digest) (lvl : MerkleLevel) : Digest :=
  match lvl.pos with
  | 0 => ro.nodeHash cur lvl.s0 lvl.s1 lvl.s2
  | 1 => ro.nodeHash lvl.s0 cur lvl.s1 lvl.s2
  | 2 => ro.nodeHash lvl.s0 lvl.s1 cur lvl.s2
  | _ => ro.nodeHash lvl.s0 lvl.s1 lvl.s2 cur

/-- Fold the authentication path from the leaf hash up to the claimed root. -/
def computeRoot (ro : RandomOracle) (leaf : Digest) (levels : List MerkleLevel) : Digest :=
  levels.foldl (stepUp ro) leaf

/--
`R_leaf ro p w` holds iff witness `w` satisfies the leaf circuit for public
inputs `p`.

NOTE (Phase-1 confirmation): the exact membership of the 32-bit range-check set
(`ZkLeaf::collect_32_bit_targets`) must be pinned by the differential tests. We
assert the bounds we have confirmed from the source (output amounts, input
amount, block number, and `fee_bps ≤ 10000`); `asset_id` and `transfer_count`
bounds are marked TODO below rather than asserted, to avoid the spec
over-claiming.
-/
def Rleaf (ro : RandomOracle) (p : LeafPublic) (w : LeafWitness) : Prop :=
  -- ── Always-on constraints ────────────────────────────────────────────────
  -- Range checks (confirmed subset).
  inRange 32 p.outputAmount1 ∧
  inRange 32 p.outputAmount2 ∧
  inRange 32 w.inputAmount ∧
  inRange 32 p.blockNumber ∧
  p.volumeFeeBps ≤ 10000 ∧
  -- TODO(Phase 1): confirm and add `inRange 32 p.assetId` and range of
  -- `w.transferCount` against `collect_32_bit_targets`.
  -- C5 fee / value conservation.
  feeOk p w ∧
  -- C2 wormhole-address derivation, plus the `to_account == account_id` wiring.
  w.toAccount = ro.WA w.secret ∧
  -- Well-formed authentication path.
  w.levels.length = w.depth ∧
  w.depth ≤ maxDepth ∧
  (∀ lvl ∈ w.levels, lvl.pos < 4) ∧
  -- ── Constraints gated on `is_not_dummy` ──────────────────────────────────
  (¬ p.isDummy →
    -- C1 nullifier.
    p.nullifier = ro.Null w.secret w.transferCount ∧
    -- C4 block-hash preimage.
    p.blockHash = ro.H (headerPreimage w p.blockNumber) ∧
    -- ZK-tree root binding: header commits to the reconstructed Merkle root.
    w.zkTreeRoot = w.rootHash ∧
    w.rootHash =
      computeRoot ro
        (ro.leafHash w.toAccount w.transferCount p.assetId w.inputAmount)
        w.levels)

end WormholeSpec
