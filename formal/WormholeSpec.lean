/-
  Formal specification of the qp-zk-circuits wormhole relations.

  This is the Phase-0 deliverable: an executable, machine-checked *specification*
  of what the leaf and aggregation circuits are supposed to mean. It is the
  artifact that Phase-2/3 soundness and completeness proofs check the circuit
  against.

  Module map:
  * `WormholeSpec.Basic`       field/digest model, salts, range predicate
  * `WormholeSpec.Hash`        hash interface (`H`, `CollisionResistant`) and derived hashes
  * `WormholeSpec.Leaf`        22-felt leaf relation R_leaf (C1–C4, conditional dummy path)
  * `WormholeSpec.Aggregation` private-batch / public-batch relations, including
                               one aggregate fee check per private segment
  * `WormholeSpec.AggregationBridge`  the private-batch/public-batch wrapper *circuit constraints* imply
                               `RPrivateBatch`/`RPublicBatch`, and a satisfied aggregation
                               circuit whose children satisfy their relations attests its
                               own + each child's relation
  * `WormholeSpec.Security`    reduction-style theorems (one-time withdrawal,
                               spend-path exclusivity): `*_or_collision` reductions
                               + corollaries under the `CollisionResistant` hypothesis
  * `WormholeSpec.Encoding`    byte↔felt encoding safety: 4-byte injective at the
                               edges, 8-byte injective only on canonical inputs

  This package is axiom-free: `#print axioms` on any theorem here names only the standard
  `propext` / `Classical.choice` / `Quot.sound`. Proof-system soundness — that a proof the
  recursive verifier gadget accepts attests the proved circuit's relation — is the one trusted
  axiom of the whole development, `Plonky2Bridge.proof_sound` in qp-plonky2/formal, stated on
  the exported recursion tree; `LeafCircuit.accepted_sound` / `Wrapper{2,4}.accepted_sound`
  there supply the child-relation hypotheses of `AggregationBridge.private_batch_sound` /
  `public_batch_sound`.

  See `SPEC.md` for the clause-by-clause cross reference to the Rust source.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf
import WormholeSpec.Aggregation
import WormholeSpec.AggregationBridge
import WormholeSpec.Security
import WormholeSpec.Encoding
import WormholeSpec.LeafBinding
