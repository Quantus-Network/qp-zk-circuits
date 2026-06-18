/-
  Byte ↔ field-element encoding safety.

  qp-poseidon / qp-zk-circuits-common expose two byte→felt encodings:

  * **4 bytes/felt + `0x01` terminator** (`bytes_to_felts`) — used at *edges*,
    i.e. attacker-controllable preimages. Each limb is a 32-bit value, strictly
    below the Goldilocks prime `p`, so the field map never reduces and the
    encoding is injective (no precondition needed).

  * **8 bytes/felt** (`bytes_to_digest`, `*_compact`) — used for *hash outputs*.
    The Rust code decodes each 8-byte little-endian limb with
    `GoldilocksField::from_noncanonical_u64`, i.e. reduction mod `p`. Two limbs
    therefore collide iff they are congruent mod `p`; on the `u64` range
    `[0, 2^64)` the only such pairs are `{w, w + p}`.

  MODELING. `u64::from_le_bytes` is a standard bijection between 8-byte chunks and
  `[0, 2^64)`, so we reason at the *limb* level: `feltOf v = v % p` is exactly
  `from_noncanonical_u64` applied to a `u64`. The security argument is then:

      SAFE  ⟺  every input to an 8-byte decode is *canonical* (each limb < p).

  Under that precondition the decode is injective (`feltOf_inj_canonical`,
  `bytesToDigest_inj_canonical`); off it a collision provably exists
  (`feltOf_not_injective`, and the exact characterisation `feltOf_collision_iff`).
  The 4-byte path is canonical *unconditionally* (`feltOf_id_of_lt_2pow32`, since
  `2^32 ≤ p`), so edges need no precondition.

  WHAT THIS DOES **NOT** SHOW. That no attacker-controllable, non-canonical byte
  string ever reaches an 8-byte decode is a property of the *callers* (genuine
  hash outputs are canonical by construction; arbitrary witnessed bytes must be
  range-checked). That obligation is the call-site audit tracked in `SPEC.md`,
  not something provable about the encoding in isolation.
-/
import WormholeSpec.Basic

namespace WormholeSpec

/-- The Goldilocks prime as a `Nat` (alias of `goldilocks`). -/
abbrev p : Nat := goldilocks

/-- `2^64`: the range of a `u64` limb produced by `u64::from_le_bytes`. -/
abbrev pow2_64 : Nat := 2 ^ 64

theorem p_pos : 0 < p := by decide
theorem p_lt_pow2_64 : p < pow2_64 := by decide
theorem pow2_64_lt_two_p : pow2_64 < 2 * p := by decide
theorem two_pow_32_le_p : 2 ^ 32 ≤ p := by decide

/-- The per-limb field map: `from_noncanonical_u64` on a `u64` value. -/
def feltOf (v : Nat) : Nat := v % p

/-- Canonical = strictly below the field modulus (a field element's unique
    representative). -/
def Canonical (v : Nat) : Prop := v < p

@[simp] theorem feltOf_id_canonical {v : Nat} (h : Canonical v) : feltOf v = v :=
  Nat.mod_eq_of_lt h

/-- 32-bit limbs (the 4-byte encoding) are canonical, hence never reduced: the
    edge encoding is lossless at the field level with no precondition. -/
theorem feltOf_id_of_lt_2pow32 {v : Nat} (h : v < 2 ^ 32) : feltOf v = v := by
  have := two_pow_32_le_p
  exact Nat.mod_eq_of_lt (by omega)

/-- The 8-byte decode is injective on canonical limbs. -/
theorem feltOf_inj_canonical {a b : Nat} (ha : Canonical a) (hb : Canonical b)
    (h : feltOf a = feltOf b) : a = b := by
  rw [feltOf_id_canonical ha, feltOf_id_canonical hb] at h
  exact h

/-- Off the canonical range the 8-byte decode is **not** injective: `0` and `p`
    are distinct `u64` limbs with the same field image. -/
theorem feltOf_not_injective :
    ∃ a b, a ≠ b ∧ a < pow2_64 ∧ b < pow2_64 ∧ feltOf a = feltOf b := by
  refine ⟨0, p, by have := p_pos; omega, by decide, p_lt_pow2_64, ?_⟩
  simp [feltOf, Nat.mod_self, Nat.zero_mod]

/-- Exact collision characterisation on `u64` limbs: equal field images means
    congruent mod `p`, and since `2^64 < 2p` that forces the limbs to be equal or
    to differ by exactly `p`. -/
theorem feltOf_collision_iff {a b : Nat} (ha : a < pow2_64) (hb : b < pow2_64) :
    feltOf a = feltOf b ↔ a = b ∨ a + p = b ∨ b + p = a := by
  unfold feltOf
  have h2p := pow2_64_lt_two_p
  rcases Nat.lt_or_ge a p with hap | hap <;> rcases Nat.lt_or_ge b p with hbp | hbp
  · rw [Nat.mod_eq_of_lt hap, Nat.mod_eq_of_lt hbp]; omega
  · rw [Nat.mod_eq_of_lt hap, Nat.mod_eq_sub_mod hbp,
        Nat.mod_eq_of_lt (show b - p < p by omega)]; omega
  · rw [Nat.mod_eq_sub_mod hap, Nat.mod_eq_of_lt (show a - p < p by omega),
        Nat.mod_eq_of_lt hbp]; omega
  · rw [Nat.mod_eq_sub_mod hap, Nat.mod_eq_of_lt (show a - p < p by omega),
        Nat.mod_eq_sub_mod hbp, Nat.mod_eq_of_lt (show b - p < p by omega)]; omega

/-- The 8-byte digest decode at the limb level: each of the (four) `u64` limbs is
    reduced mod `p`. -/
def bytesToDigest (limbs : List Nat) : List Nat := limbs.map feltOf

/-- The digest decode is injective on canonical limb lists: this is the formal
    content of "the 8-byte encoding is safe for hash outputs". -/
theorem bytesToDigest_inj_canonical :
    ∀ {l₁ l₂ : List Nat},
      (∀ v ∈ l₁, Canonical v) → (∀ v ∈ l₂, Canonical v) →
      bytesToDigest l₁ = bytesToDigest l₂ → l₁ = l₂ := by
  intro l₁
  induction l₁ with
  | nil =>
      intro l₂ _ _ h
      cases l₂ with
      | nil => rfl
      | cons y ys => simp [bytesToDigest] at h
  | cons x xs ih =>
      intro l₂ h₁ h₂ h
      cases l₂ with
      | nil => simp [bytesToDigest] at h
      | cons y ys =>
          simp only [bytesToDigest, List.map_cons, List.cons.injEq] at h
          obtain ⟨hh, ht⟩ := h
          have hx : Canonical x := h₁ x List.mem_cons_self
          have hy : Canonical y := h₂ y List.mem_cons_self
          have hxy : x = y := feltOf_inj_canonical hx hy hh
          have hxs : xs = ys :=
            ih (fun v hv => h₁ v (List.mem_cons_of_mem x hv))
               (fun v hv => h₂ v (List.mem_cons_of_mem y hv))
               ht
          rw [hxy, hxs]

end WormholeSpec
