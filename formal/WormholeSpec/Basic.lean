/-
  Basic field/digest model and shared constants.

  PHASE-0 MODELING CHOICE
  -----------------------
  `Felt` is a *placeholder* for a Goldilocks field element, currently `Nat`. At
  the specification level the relations need only (a) hash I/O over felts and
  (b) range / encoding facts on small scalars. The latter are modeled *explicitly*
  over `Nat` with the modulus `goldilocks` (see `Encoding.lean`, which reasons
  about `· % p` directly), so they never require `Felt` itself to be the finite
  field.

  WARNING — the field representation is NOT a free global swap.
  -----------------------------------------------------------
  Do **not** redefine `abbrev Felt := ZMod goldilocks` workspace-wide. `Hash.lean`
  models the hash as a *totally injective* `H : List Felt → Digest` (the
  random-oracle idealization). That is satisfiable only while the carrier is
  infinite — as `Nat` is, so `RandomOracle` is inhabited today and the security
  theorems have content. Over a *finite* `Felt`, `Digest = Felt⁴` is finite while
  `List Felt` is infinite, so by pigeonhole no injective `H` exists ⇒
  `RandomOracle` becomes uninhabited ⇒ every RO-dependent theorem
  (`Security.lean`, `LeafBinding.lean`) silently turns vacuous. See the matching
  warning in `Hash.lean`.

  Consequently the interactive in-field arithmetic (Phase 2) and the game-based
  collision / preimage resistance (Phase 4) belong in their own concrete-field
  layer; the RO-dependent modules must stay over an infinite / abstract `Felt`.
-/

namespace WormholeSpec

/-- A Goldilocks field element (Phase-0 placeholder; see module header). -/
abbrev Felt : Type := Nat

/-- The Goldilocks prime `2^64 - 2^32 + 1`. Used as the explicit modulus by the
    encoding / range layer (`Encoding.lean`); the RO layer deliberately does *not*
    make this the modulus of `Felt` (see the warning in the module header). -/
def goldilocks : Nat := 0xFFFFFFFF00000001

/-- A 256-bit digest: four field elements, matching `POSEIDON2_OUTPUT = 4` and the
    `Digest`/`HashOut` types in the Rust circuit. -/
structure Digest where
  x0 : Felt
  x1 : Felt
  x2 : Felt
  x3 : Felt
  deriving DecidableEq, Repr

namespace Digest

/-- Flatten a digest to the felt list used as hash preimage material. -/
def toList (d : Digest) : List Felt := [d.x0, d.x1, d.x2, d.x3]

/-- The all-zero digest, used as the dummy-proof sentinel for `block_hash`. -/
def zero : Digest := ⟨0, 0, 0, 0⟩

end Digest

/-- `inRange bits x` models an in-circuit `range_check(x, bits)`: the felt is the
    canonical representative of a `bits`-bit natural (no field wraparound). -/
def inRange (bits : Nat) (x : Felt) : Prop := x < 2 ^ bits

/-- Domain-separation salt `string_to_felts("wormhole")` used by `WA`.
    Length 3 (`UNSPENDABLE` `PREIMAGE_NUM_TARGETS = 3 + 4`). The concrete felt
    values are pinned by the Phase-1 differential tests; here it is an abstract
    but fixed constant. -/
opaque wormholeSalt : List Felt

/-- Domain-separation salt `string_to_felts("~nullif~")` used by `Null`.
    Length 3 (`SALT_NUM_TARGETS = 3`). -/
opaque nullifierSalt : List Felt

end WormholeSpec
