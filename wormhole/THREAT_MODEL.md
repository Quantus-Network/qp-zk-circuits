# Wormhole threat model (artifact generation & loading)

This document states the **trust boundaries** for Wormhole circuit artifacts
and aggregation. Review findings that assume a different boundary (especially
a hostile local filesystem on the build host) are **out of scope** unless that
assumption is explicitly adopted later.

Related: [Nullifiers and double-spend prevention](./README.md#nullifiers-and-double-spend-prevention-security-model)
(settlement is on-chain; aggregators are untrusted for spend uniqueness).

---

## Roles

| Role | Trust |
|---|---|
| **CI / build host** running `qp-wormhole-circuit-builder` | **Trusted** for artifact *generation*. The host, its toolchain, the checkout, and the output parent directory during the build are not an adversarial environment. |
| **Artifact directory after CI attestation** | **Trusted origin**. Nodes and operators load bins only from CI-produced (or equivalently attested) paths — not from arbitrary untrusted uploads. |
| **Aggregator / miner operators** | **Untrusted for soundness**. They may omit, delay, or select proofs; they must not be able to mint value or forge verifying proofs. Operational DoS against a single miner is not a protocol-soundness bug. |
| **Clients submitting proofs** | **Untrusted**. Proofs are attacker-controlled byte strings until cryptographic verification succeeds. |
| **On-chain verifier / wormhole pallet** | **Trusted** for settlement rules (nullifier set, fee config, etc.). |

---

## Explicitly out of scope

The following are **not** security requirements for the circuit-builder or for
loading CI-attested artifact directories. They assume a **local adversary with
write access to the build output parent (or the bins directory) concurrent
with generation/loading** — incompatible with “CI-generated, trusted build
host.”

- Symlink planting / TOCTOU on staging or artifact pathnames during publish
- FIFOs, device nodes, or sparse files planted at artifact names to hang or
  inflate readers during a trusted build
- Basename / path-escape attacks against a trusted builder writing into its
  own output directory
- Concurrent replacement of a staging directory mid-build by another local
  process on the build host
- Treating “cleanup of a moved-aside previous output failed” as equivalent to
  “publish failed” for soundness (it is an operational concern only)

Those publisher/local-FS defenses have been **removed** from the builder and
artifact I/O paths to match this model. What remains for operator hygiene:

- Whole-directory staging in `generate_all_circuit_binaries` (avoids mixed
  leaf / private-batch / public-batch generations on a failed mid-pipeline run)
- Size caps on artifact reads before canonical pinning
- Best-effort cleanup warnings after a successful directory swap

Do not reintroduce symlink/FIFO/TOCTOU/basename hardening as “security
requirements” without first changing this document.

---

## Still in scope (do not regress)

Even with a trusted build host, the following remain required:

1. **No shipped prover binaries**  
   Leaf / private-batch / public-batch provers rebuild proving key material
   from source. A `prover.bin` could choose which witness wires become public
   inputs and exfiltrate secrets through the proof.

2. **Canonical verifier pinning at load time**  
   Loaded `common.bin` / `verifier.bin` (and private-batch equivalents) must
   match a rebuild of the expected circuit for the configured shape. This
   catches **wrong version, wrong shape, or accidental mix-ups** — not only
   malice. Prefer comparing raw artifact bytes to a canonical serialization
   so untrusted-looking length fields are never deserialized blindly.

3. **Dummy padding template validation**  
   `dummy_proof.bin` / `dummy_private_batch_proof.bin` must carry the dummy
   sentinel and verify, so padding cannot inject real exits/nullifiers into
   partial batches.

4. **Untrusted proof admission**  
   Proofs from the network are verified (and rate-limited as needed) before
   pool state or membership oracles are consulted. Aggregators remain
   untrusted for nullifier uniqueness; the chain is the double-spend boundary.

5. **Config / shape bounds**  
   `num_leaf_proofs` and `num_private_batch_proofs` stay within
   `1..=MAX_PROOF_COUNT` before circuit construction.

---

## Operational requirements (trusted path)

To stay inside this model, deployments should:

1. Build artifacts in CI (or an equivalently controlled builder) from a pinned
   commit/toolchain.
2. Distribute the artifact directory via an attested channel (release asset,
   content-addressed store, image layer, etc.).
3. Point provers/verifiers only at that attested path — do not accept
   operator- or user-supplied bins directories as equivalent to CI output without
   re-attestation.
4. Treat a bins directory of unknown provenance as **untrusted input**: either
   refuse it or re-run the builder and pin.

If a deployment *does* load bins from untrusted hosts or shared writable
directories, that is a **different threat model** and must be documented as
such; the out-of-scope list above becomes in-scope again.

---

## Audit guidance

When filing issues against `circuit-builder`, `commit_artifact_set`, staging
renames, or artifact readers:

| Finding class | Under this model |
|---|---|
| Local FS race / symlink / FIFO on the **build host during CI generation** | Out of scope — note the assumption, do not treat as a protocol defect |
| Poisoned or mismatched bins loaded by a **prover/verifier** | In scope if it bypasses canonical pin, dummy checks, or ships prover-only data |
| Invalid client proof affecting **pool membership oracles** or skipping verify | In scope |
| Aggregator learning or omitting metadata | Usually operational / privacy of the miner, not minting — classify carefully |
| Nullifier reuse accepted **on-chain** | In scope for the pallet (chain repo), not for circuits proving uniqueness |

Point reviewers at this file and at the nullifier section of
[`README.md`](./README.md) before classifying build-host filesystem issues as
soundness bugs.
