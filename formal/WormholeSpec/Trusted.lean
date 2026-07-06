/-
  The trusted base (T4 + the seam to layer 1).

  Everything else in `WormholeSpec` is a theorem about explicit relations. This
  module is the *opposite*: it enumerates, as explicit Lean `axiom`s, the
  assumptions the aggregation soundness argument is allowed to invoke but does not
  prove. Each is the boundary to a body of work that is out of scope for this
  spec-level development (a full machine-checked SNARK verifier), and each is
  documented with (a) what it asserts, (b) why it is justified, and (c) what it
  would take to discharge. This mirrors how `RandomOracle.CollisionResistant` makes the
  collision-resistance idealization an explicit, opt-in hypothesis rather than hidden.

  WHY AXIOMS, NOT DEFINITIONS. The recursive verifier gadget
  (`add_recursive_verifiers` → `builder.verify_proof`, baking the child verifier key
  in as constants) constrains that a child proof is valid under the proof system.
  Turning "the recursion gadget is satisfied" into "the child's public-input relation
  holds" is precisely *proof-system soundness* (FRI query soundness, the Plonk/AIR
  arithmetization, Fiat–Shamir — QROM Fiat–Shamir for the post-quantum claims — and
  the recursion composition). Formalizing that is a multi-year effort; here it is the
  trusted seam, the rung labeled `(1)` in `qp-plonky2/formal/PLAN.md` §1.

  These axioms are intentionally confined to this file; only `AggregationBridge`'s
  end-to-end soundness theorems (`private_batch_sound`, `public_batch_sound`) invoke them, so a
  `#print axioms` on any other result stays free of them.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf
import WormholeSpec.Aggregation

namespace WormholeSpec

/-! ### The recursive-verifier acceptance predicates (abstract)

These stand for "the in-circuit recursive verifier accepted a child proof whose
public inputs decode to this structure, under the *constant* (baked-in) child
verifier key." They are `opaque`, not `axiom`s: abstract predicates whose truth is
never assumed (the spec never inspects how the gadget works, only what its
satisfaction attests via the soundness *axioms* below), so they stay out of the
trusted axiom set. Realized in Rust by
`wormhole/aggregator/src/common/recursive.rs::add_recursive_verifiers`. -/

/-- A private-batch aggregation circuit accepted a recursive **leaf** proof whose 21-felt
    public inputs decode to `p`. (Constant leaf verifier key; one per leaf slot.)

    `opaque`, not `axiom`: this is an *abstract predicate* (its truth value is never
    assumed), so it should not enlarge the trusted axiom set. Only the soundness facts
    below (`leaf_proof_sound`, `private_batch_proof_sound`) are genuine `axiom`s. -/
opaque LeafProofAccepted (ro : RandomOracle) (p : LeafPublic) : Prop

/-- A public-batch aggregation circuit accepted a recursive **private-batch** proof whose public
    inputs decode to `out`. (Constant private-batch verifier key; one per inner slot.)

    `opaque` for the same reason as `LeafProofAccepted`: an abstract predicate, not an
    assumed truth. -/
opaque PrivateBatchProofAccepted (ro : RandomOracle) (out : PrivateBatchOutput) : Prop

/-! ### `verify_proof` soundness (T4) -/

/--
**TRUSTED (T4 + proof-system soundness (1)).** `verify_proof` soundness for the leaf
circuit: if the private-batch recursion gadget accepts a leaf proof (under the baked leaf
verifier key), then its public inputs satisfy the leaf relation `Rleaf` for some
witness.

*Justification.* Given proof-system soundness (1), a satisfied recursion gadget
implies the child proof is valid, hence (by the leaf circuit's own
constraints-⟺-`Rleaf` bridge, T0–T3) `Rleaf` holds on the child's public inputs.

*To discharge:* (i) a verified plonky2 verifier (FRI + Plonk + Fiat–Shamir +
recursion), and (ii) the leaf circuit ⟺ `Rleaf` bridge. (ii) is the T0–T3 program in
`qp-plonky2/formal`; (i) is rung (1), out of scope. -/
axiom leaf_proof_sound (ro : RandomOracle) (p : LeafPublic) :
    LeafProofAccepted ro p → ∃ w : LeafWitness, Rleaf ro p w

/--
**TRUSTED (T4 + proof-system soundness (1)).** `verify_proof` soundness for the
private-batch circuit: if the public-batch recursion gadget accepts a private-batch proof (under the
baked private-batch verifier key), then its public inputs satisfy the private-batch relation
`RPrivateBatch` for some children and dummy-nullifier preimages.

*Justification & discharge:* as `leaf_proof_sound`, with the private-batch circuit ⟺ `RPrivateBatch`
bridge (`AggregationBridge.private_batch_bridge`) playing the role of the child-circuit
bridge — so this axiom's (ii) component is itself a *theorem* here; only the
proof-system-soundness component (i) remains genuinely trusted. -/
axiom private_batch_proof_sound (ro : RandomOracle) (out : PrivateBatchOutput) :
    PrivateBatchProofAccepted ro out → ∃ leaves us, RPrivateBatch ro leaves us out

end WormholeSpec
