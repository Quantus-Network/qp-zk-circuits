/-
  Formal specification of the qp-zk-circuits wormhole relations.

  This is the Phase-0 deliverable: an executable, machine-checked *specification*
  of what the leaf and aggregation circuits are supposed to mean. It is the
  artifact that Phase-2/3 soundness and completeness proofs check the circuit
  against.

  Module map:
  * `WormholeSpec.Basic`       field/digest model, salts, range predicate
  * `WormholeSpec.Hash`        random-oracle interface and derived hashes
  * `WormholeSpec.Leaf`        leaf relation R_leaf (C1–C5, conditional dummy path)
  * `WormholeSpec.Aggregation` layer-0 / layer-1 aggregation relations

  See `SPEC.md` for the clause-by-clause cross reference to the Rust source.
-/
import WormholeSpec.Basic
import WormholeSpec.Hash
import WormholeSpec.Leaf
import WormholeSpec.Aggregation
