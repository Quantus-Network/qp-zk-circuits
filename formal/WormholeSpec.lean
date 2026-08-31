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
  * `WormholeSpec.Trusted`     the trusted base (T4): explicit `axiom`s for the
                               recursive-verifier (`verify_proof`) soundness
  * `WormholeSpec.AggregationBridge`  the private-batch/public-batch wrapper *circuit constraints* imply
                               `RPrivateBatch`/`RPublicBatch`, and (with `Trusted`) a satisfied
                               aggregation circuit attests its own + each child's relation
  * `WormholeSpec.Security`    reduction-style theorems (one-time withdrawal,
                               spend-path exclusivity): `*_or_collision` reductions
                               + corollaries under the `CollisionResistant` hypothesis
  * `WormholeSpec.Encoding`    byte↔felt encoding safety: 4-byte injective at the
                               edges, 8-byte injective only on canonical inputs

  See `SPEC.md` for the clause-by-clause cross reference to the Rust source.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf
import WormholeSpec.Aggregation
import WormholeSpec.Trusted
import WormholeSpec.AggregationBridge
import WormholeSpec.Security
import WormholeSpec.Encoding
import WormholeSpec.LeafBinding
