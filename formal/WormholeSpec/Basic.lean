/-
  Basic field/digest model and shared constants.

  PHASE-0 MODELING CHOICE
  -----------------------
  `Felt` is a *placeholder* for a Goldilocks field element. At the specification
  level the only field facts the relations need are (a) hash I/O over felts and
  (b) range bounds on small scalars, both of which `Nat` models faithfully.

  Phase 2 (interactive proofs) replaces this single abbreviation with
  `abbrev Felt := ZMod 0xFFFFFFFF00000001` from mathlib and adds the algebraic
  reasoning (and the CVC5 finite-field tactic) needed for in-field arithmetic.
  Nothing else in the spec references the representation, so the swap is local.
-/

namespace WormholeSpec

/-- A Goldilocks field element (Phase-0 placeholder; see module header). -/
abbrev Felt : Type := Nat

/-- The Goldilocks prime `2^64 - 2^32 + 1`. Documentation only at the spec level;
    becomes the modulus of `Felt` in Phase 2. -/
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
