/-
  The leaf relation R_leaf (paper §3.3, constraints C1–C4).

  STRUCTURE
  ---------
  The Rust circuit applies most constraints unconditionally and gates only three
  on `is_not_dummy` (see `connect_shared_targets`):

    * C1 nullifier hash,
    * C4 block-hash preimage,
    * the ZK-tree root binding `header.zk_tree_root == merkle_root`.

  Everything else (range checks, C2 wormhole-address derivation, the leaf-hash
  computation, the Merkle walk, and the shared-target equalities) holds for dummy
  and non-dummy proofs alike. Fee conservation is deliberately absent: it is
  enforced once over the dummy-masked totals of each private batch in
  `RPrivateBatch`. `R_leaf` mirrors that split exactly. Shared-target equalities
  (`nullifier.secret == account.secret`, `transfer_count` agreement,
  `to_account == account_id`) are encoded structurally by reusing the same
  witness fields rather than as separate clauses.
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

/-- The 22-felt intermediate public input vector of a leaf proof (see
    `qp-wormhole-inputs`).
    `exitAccount1/2` are public but *unconstrained* at the leaf — they are bound
    only by the private-batch aggregator — so they deliberately appear here yet are
    referenced by no clause of `R_leaf`. `inputAmount` is the appended 22nd felt:
    the private-batch wrapper consumes it for aggregate fee conservation, but it is
    not forwarded by private- or public-batch proofs. -/
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
  inputAmount : Felt
  deriving Repr

/-- The private witness of a leaf proof. -/
structure LeafWitness where
  secret : Digest
  /-- Transfer count `c`, 2 felts (`FELTS_PER_U64`). -/
  transferCount : List Felt
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

RANGE-CHECK SET (confirmed against `ZkLeaf::collect_32_bit_targets`): the
unconditional 32-bit checks cover `transfer_count` (both limbs), `asset_id`,
`input_amount`, `output_amount_1`, `output_amount_2`, and `volume_fee_bps`.
`block_number`'s 32-bit check lives separately in
`BlockHeader::circuit_without_hash_binding` (also
unconditional). The leaf does not impose the binding `volume_fee_bps ≤ 10000`
check: the private-batch relation imposes it once together with the aggregate fee
inequality.
-/
def Rleaf (ro : RandomOracle) (p : LeafPublic) (w : LeafWitness) : Prop :=
  -- ── Always-on constraints ────────────────────────────────────────────────
  -- 32-bit range checks (`collect_32_bit_targets` + the block-header check).
  inRange 32 p.outputAmount1 ∧
  inRange 32 p.outputAmount2 ∧
  inRange 32 p.inputAmount ∧
  inRange 32 p.assetId ∧
  inRange 32 p.volumeFeeBps ∧
  inRange 32 p.blockNumber ∧
  w.transferCount.length = 2 ∧
  (∀ t ∈ w.transferCount, inRange 32 t) ∧
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
        (ro.leafHash w.toAccount w.transferCount p.assetId p.inputAmount)
        w.levels)

end WormholeSpec
