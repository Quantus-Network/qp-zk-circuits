use alloc::{format, string::String, vec::Vec};
use core::fmt;
use core::marker::PhantomData;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};
use serde::de::{self, Deserializer, Error, SeqAccess, Visitor};
use serde::Deserialize;

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField; // Goldilocks field

/// Maximum number of hex-encoded storage-proof nodes accepted in [`TransferProofJson`].
pub const MAX_STORAGE_PROOF_NODES: usize = 1024;
/// Maximum hex-string length of one storage-proof node.
pub const MAX_STORAGE_PROOF_NODE_HEX_LEN: usize = 1 << 20;
/// Maximum aggregate hex-string length across all storage-proof nodes.
pub const MAX_STORAGE_PROOF_HEX_BYTES: usize = 1 << 20;
/// Maximum number of Merkle indices accepted in [`TransferProofJson`].
pub const MAX_MERKLE_INDICES: usize = 1024;
/// Maximum byte length of the hex `state_root` string in [`TransferProofJson`].
pub const MAX_STATE_ROOT_HEX_LEN: usize = 64;
/// Maximum raw byte length of a serialized [`TransferProofJson`] document.
///
/// The per-field caps above bound what a parsed document may contain, but they
/// are enforced from inside Serde visitor callbacks — by the time a visitor
/// sees a string's length, the deserializer has already decoded any escaped
/// content into scratch storage. Only a cap on the raw, undecoded input can
/// bound that allocation. 8 MiB is ~8x the largest in-bounds document
/// (storage_proof dominates at 1 MiB of hex), leaving room for maximally
/// escape-inflated (6 bytes per decoded byte) but otherwise legal payloads.
pub const MAX_TRANSFER_PROOF_JSON_BYTES: usize = 8 * 1024 * 1024;

/// A parsed transfer-proof document.
///
/// This type deliberately does NOT implement `serde::Deserialize`: generic
/// entry points (`serde_json::from_str`, `from_slice`, and especially the
/// streaming `from_reader`) would bypass the raw-input cap that
/// [`Self::from_json_str`] enforces, and the per-field visitor bounds alone
/// cannot stop a streamed, escape-inflated string from being decoded into
/// unbounded scratch storage first. All parsing must go through
/// [`Self::from_json_str`].
///
/// ```compile_fail
/// fn requires_deserialize<'de, T: serde::Deserialize<'de>>() {}
/// requires_deserialize::<qp_zk_circuits_common::circuit::TransferProofJson>();
/// ```
///
/// The passing companion below exercises the same fully qualified path (and
/// the sanctioned parse route). A `compile_fail` test asserts only that
/// *some* compile error occurs, so on its own it would keep passing — for
/// the wrong reason — if the crate were renamed, the module moved, or serde
/// stopped resolving in the doctest environment. Any of those now breaks
/// this visible test instead of silently disarming the pin above.
///
/// ```
/// use serde::Deserialize as _; // serde must resolve here for the pin to be meaningful
/// let doc = qp_zk_circuits_common::circuit::TransferProofJson::from_json_str(
///     r#"{"transfer_count":1,"state_root":"00","storage_proof":["00"],"indices":[0]}"#,
/// ).unwrap();
/// assert_eq!(doc.transfer_count, 1);
/// ```
#[derive(Debug)]
pub struct TransferProofJson {
    pub transfer_count: u64,
    pub state_root: String,         // hex (no 0x)
    pub storage_proof: Vec<String>, // hex-encoded nodes
    pub indices: Vec<usize>,
}

/// Private deserialization target for [`TransferProofJson::from_json_str`].
///
/// The `Deserialize` impl lives on this non-public mirror so the only way to
/// parse a [`TransferProofJson`] is through the raw-capped entry point; the
/// per-field bounds below are defense in depth behind that cap, not a
/// substitute for it.
#[derive(Deserialize)]
struct TransferProofJsonRaw {
    transfer_count: u64,
    #[serde(deserialize_with = "deserialize_bounded_state_root")]
    state_root: String,
    #[serde(deserialize_with = "deserialize_bounded_storage_proof")]
    storage_proof: Vec<String>,
    #[serde(deserialize_with = "deserialize_bounded_indices")]
    indices: Vec<usize>,
}

impl From<TransferProofJsonRaw> for TransferProofJson {
    fn from(raw: TransferProofJsonRaw) -> Self {
        Self {
            transfer_count: raw.transfer_count,
            state_root: raw.state_root,
            storage_proof: raw.storage_proof,
            indices: raw.indices,
        }
    }
}

impl TransferProofJson {
    /// Parse untrusted transfer-proof JSON, bounding allocation up front.
    ///
    /// This is the ONLY parse path (the type does not implement
    /// `Deserialize`; see the type-level docs). The raw document length is
    /// checked against [`MAX_TRANSFER_PROOF_JSON_BYTES`] BEFORE any parsing:
    /// the per-field Serde bounds only observe string lengths after the
    /// deserializer has decoded escaped content into scratch storage, so on
    /// their own they cannot stop a single escape-inflated field from
    /// allocating and scanning arbitrarily far past its cap before being
    /// rejected.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        if json.len() > MAX_TRANSFER_PROOF_JSON_BYTES {
            return Err(format!(
                "transfer proof JSON exceeds {} bytes ({} bytes); refusing to parse it",
                MAX_TRANSFER_PROOF_JSON_BYTES,
                json.len()
            ));
        }
        serde_json::from_str::<TransferProofJsonRaw>(json)
            .map(Self::from)
            .map_err(|e| format!("failed to parse transfer proof JSON: {e}"))
    }

    /// Validate the decoded transfer proof bounds.
    ///
    /// Parsed documents already satisfy these caps (the private
    /// deserialization mirror enforces them per field, behind
    /// [`Self::from_json_str`]'s raw-input bound); this is a convenience
    /// check for callers that construct the struct directly.
    pub fn validate(&self) -> Result<(), String> {
        if self.state_root.len() > MAX_STATE_ROOT_HEX_LEN {
            return Err(format!(
                "state_root exceeds {} bytes",
                MAX_STATE_ROOT_HEX_LEN
            ));
        }
        if self.storage_proof.len() > MAX_STORAGE_PROOF_NODES {
            return Err(format!(
                "storage_proof exceeds {} nodes",
                MAX_STORAGE_PROOF_NODES
            ));
        }
        let mut total_storage_proof_bytes = 0usize;
        for (index, node) in self.storage_proof.iter().enumerate() {
            if node.len() > MAX_STORAGE_PROOF_NODE_HEX_LEN {
                return Err(format!(
                    "storage_proof node {} exceeds {} bytes",
                    index, MAX_STORAGE_PROOF_NODE_HEX_LEN
                ));
            }
            total_storage_proof_bytes = total_storage_proof_bytes
                .checked_add(node.len())
                .ok_or_else(|| String::from("storage_proof total byte length overflow"))?;
            if total_storage_proof_bytes > MAX_STORAGE_PROOF_HEX_BYTES {
                return Err(format!(
                    "storage_proof exceeds {} total bytes",
                    MAX_STORAGE_PROOF_HEX_BYTES
                ));
            }
        }
        if self.indices.len() > MAX_MERKLE_INDICES {
            return Err(format!("indices exceeds {} entries", MAX_MERKLE_INDICES));
        }
        Ok(())
    }
}

/// Deserialize a hex `state_root` string, rejecting inputs longer than
/// [`MAX_STATE_ROOT_HEX_LEN`] before allocating the owned `String`.
///
/// NOTE: for escaped or streamed input the deserializer must decode the string
/// into its own scratch storage before this visitor can observe the length, so
/// this bound alone does not cap allocation. That is why these visitors are
/// only reachable through [`TransferProofJson::from_json_str`], which bounds
/// the raw document first.
fn deserialize_bounded_state_root<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct StateRootVisitor;
    impl<'de> Visitor<'de> for StateRootVisitor {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "a hex state_root string of at most {} bytes",
                MAX_STATE_ROOT_HEX_LEN
            )
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<String, E> {
            if v.len() > MAX_STATE_ROOT_HEX_LEN {
                return Err(E::custom(format!(
                    "state_root exceeds {} bytes",
                    MAX_STATE_ROOT_HEX_LEN
                )));
            }
            Ok(String::from(v))
        }
        fn visit_string<E: Error>(self, v: String) -> Result<String, E> {
            if v.len() > MAX_STATE_ROOT_HEX_LEN {
                return Err(E::custom(format!(
                    "state_root exceeds {} bytes",
                    MAX_STATE_ROOT_HEX_LEN
                )));
            }
            Ok(v)
        }
    }
    deserializer.deserialize_str(StateRootVisitor)
}

/// Deserialize a `Vec<T>` from a sequence, stopping and failing once the element
/// count exceeds `max` so oversized inputs are rejected before the full allocation.
fn deserialize_bounded_vec<'de, T, D>(
    deserializer: D,
    max: usize,
    label: &'static str,
) -> Result<Vec<T>, D::Error>
where
    T: de::Deserialize<'de>,
    D: Deserializer<'de>,
{
    struct BoundedSeqVisitor<T> {
        max: usize,
        label: &'static str,
        _phantom: PhantomData<T>,
    }
    impl<'de, T: de::Deserialize<'de>> Visitor<'de> for BoundedSeqVisitor<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "a sequence of at most {} items ({})",
                self.max, self.label
            )
        }
        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<T>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let cap = seq.size_hint().unwrap_or(0).min(self.max);
            let mut out = Vec::with_capacity(cap);
            while let Some(item) = seq.next_element()? {
                if out.len() >= self.max {
                    return Err(A::Error::custom(format!(
                        "{} exceeds {} items",
                        self.label, self.max
                    )));
                }
                out.push(item);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_seq(BoundedSeqVisitor {
        max,
        label,
        _phantom: PhantomData,
    })
}

fn deserialize_bounded_storage_proof<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStorageNode(String);

    impl<'de> de::Deserialize<'de> for BoundedStorageNode {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct NodeVisitor;
            impl Visitor<'_> for NodeVisitor {
                type Value = BoundedStorageNode;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        f,
                        "a storage-proof hex string of at most {} bytes",
                        MAX_STORAGE_PROOF_NODE_HEX_LEN
                    )
                }

                fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                    if value.len() > MAX_STORAGE_PROOF_NODE_HEX_LEN {
                        return Err(E::custom(format!(
                            "storage_proof node exceeds {} bytes",
                            MAX_STORAGE_PROOF_NODE_HEX_LEN
                        )));
                    }
                    Ok(BoundedStorageNode(String::from(value)))
                }

                fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
                    if value.len() > MAX_STORAGE_PROOF_NODE_HEX_LEN {
                        return Err(E::custom(format!(
                            "storage_proof node exceeds {} bytes",
                            MAX_STORAGE_PROOF_NODE_HEX_LEN
                        )));
                    }
                    Ok(BoundedStorageNode(value))
                }
            }

            deserializer.deserialize_str(NodeVisitor)
        }
    }

    struct StorageProofVisitor;
    impl<'de> Visitor<'de> for StorageProofVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "at most {} storage-proof nodes totaling at most {} bytes",
                MAX_STORAGE_PROOF_NODES, MAX_STORAGE_PROOF_HEX_BYTES
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let cap = seq.size_hint().unwrap_or(0).min(MAX_STORAGE_PROOF_NODES);
            let mut out = Vec::with_capacity(cap);
            let mut total_bytes = 0usize;

            while out.len() < MAX_STORAGE_PROOF_NODES {
                let Some(BoundedStorageNode(node)) = seq.next_element()? else {
                    return Ok(out);
                };
                total_bytes = total_bytes
                    .checked_add(node.len())
                    .ok_or_else(|| A::Error::custom("storage_proof total byte length overflow"))?;
                if total_bytes > MAX_STORAGE_PROOF_HEX_BYTES {
                    return Err(A::Error::custom(format!(
                        "storage_proof exceeds {} total bytes",
                        MAX_STORAGE_PROOF_HEX_BYTES
                    )));
                }
                out.push(node);
            }

            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(format!(
                    "storage_proof exceeds {} items",
                    MAX_STORAGE_PROOF_NODES
                )));
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(StorageProofVisitor)
}

fn deserialize_bounded_indices<'de, D>(deserializer: D) -> Result<Vec<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_MERKLE_INDICES, "indices")
}

/// Circuit config for leaf wormhole proofs (non-ZK).
///
/// Since the chain only verifies aggregated proofs (not individual leaf proofs), there's no
/// privacy benefit from using ZK on the leaves. Disabling ZK gives faster proving and smaller
/// proofs without compromising security - the aggregator that verifies these proofs runs in a
/// trusted environment anyway.
pub fn wormhole_leaf_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config() // zero_knowledge: false
}

/// Circuit config for private-batch aggregation circuits (ZK enabled via row blinding).
///
/// Private-batch is the *private* aggregation layer: its witnesses are the leaf proofs, whose
/// own witnesses (spend secrets, Merkle paths) must never leak. This is the one layer in
/// the stack that requires zero-knowledge.
///
/// This config uses:
/// - Row blinding ZK mode (lower memory than PolyFri, same security)
/// - num_wires = 135 (minimum for PoseidonGate)
/// - num_routed_wires = 60 (optimal for degree_bits=15 circuits)
///
/// Memory usage by batch size (with this config):
/// - 7 leaves: degree_bits=15, ~1.5 GB peak (recommended for mobile)
/// - 8+ leaves: degree_bits=16, ~2.5 GB peak (requires 6GB+ device RAM)
pub fn wormhole_private_batch_circuit_config() -> CircuitConfig {
    CircuitConfig {
        num_wires: 135,
        num_routed_wires: 60,
        ..CircuitConfig::standard_recursion_zk_config()
    }
}

/// Circuit config for public-batch aggregation circuits (non-ZK).
///
/// Public-batch is the *public* aggregation layer: its witnesses are private-batch proofs, which are
/// (a) themselves zero-knowledge, so their bytes reveal nothing about the leaves, and
/// (b) handed to the aggregator in plaintext anyway, with every private-batch public input
/// forwarded verbatim into the public-batch public inputs. A non-ZK public-batch proof therefore
/// cannot leak anything that is not already public. Disabling ZK (row blinding) here
/// significantly speeds up proving, mirroring `wormhole_leaf_circuit_config`.
pub fn wormhole_public_batch_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config() // zero_knowledge: false
}

// ============================================================================
// CircuitConfig structural validation
// ============================================================================
//
// Shared policy enforced by every public Wormhole circuit constructor before
// the config reaches `CircuitBuilder::new` (audit finding: constructors
// treated caller-supplied `CircuitConfig` as trusted, so structurally
// impossible values panicked deep inside plonky2 mid-construction and
// resource-pathological values caused exponential allocations during the
// expensive build phase). The same floors/ceilings back the memprof CLI's
// flag validation; keep them here so the two policies cannot drift.

/// The Poseidon gate needs 135 wire columns; a smaller `num_wires` panics
/// deep inside plonky2's `check_gate_compatibility` mid-build instead of
/// failing at the API boundary.
pub const MIN_NUM_WIRES: usize = 135;

/// Structural routed-wire floor for the pinned plonky2 recursion stack.
///
/// Gates pack operations into the routed-wire prefix, and several derive
/// their op count from `num_routed_wires`: base arithmetic uses 4 routed
/// wires per op, extension arithmetic `4*D = 8`, and the FRI verifier's
/// random-access gate `2 + 2^4 = 18` per copy. Below a gate's width it
/// instantiates with ZERO operation slots: `find_slot`'s `num_ops - 1`
/// underflows (debug panic; in release an under-constraining zero-op gate is
/// added and the build only dies later on a routability assert). The binding
/// floor is the 16-point coset-interpolation gate, which routes
/// `1 + 16*D + D + D = 37` wires outright; plonky2's own
/// `check_recursion_config` assert for it fires only mid-build.
pub const MIN_NUM_ROUTED_WIRES: usize = 37;

/// Poseidon constraints have degree 7; a smaller quotient degree factor
/// cannot express them and fails during circuit construction.
pub const MIN_MAX_QUOTIENT_DEGREE_FACTOR: usize = 7;

/// Ceiling for FRI `rate_bits`. The exponent drives exponential allocations
/// deep inside plonky2 (`FriParams::lde_size` is
/// `1 << (degree_bits + rate_bits)` per committed polynomial), so an
/// oversized value passes construction and then makes massive allocations or
/// trips asserts only after the expensive circuit build has started.
/// Production is 3; 8 already means a 32x-production LDE.
pub const MAX_RATE_BITS: usize = 8;

/// Ceiling for FRI `cap_height`. The Merkle cap is `1 << cap_height` hashes
/// per oracle, and the recursive verifier allocates `1 << cap_height` hash
/// targets for the verifier data (`add_virtual_cap`), all registered as
/// public inputs — so this knob blows up circuit size exponentially, not
/// just proof size. `MerkleTree::new` additionally asserts
/// `cap_height <= degree_bits + rate_bits` only mid-build; with the cap
/// bounded at 8 (16x the production cap of 4) that assert is unreachable
/// for any real Wormhole circuit (`degree_bits >= 12`), so the bound also
/// serves as the cap/degree consistency guard.
pub const MAX_CAP_HEIGHT: usize = 8;

/// `ceil(log2(n))` for `n >= 1`, mirroring plonky2's `log2_ceil`.
fn log2_ceil(n: usize) -> usize {
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// Structural and resource-bound validation for a caller-supplied
/// [`CircuitConfig`], enforced by every public Wormhole circuit constructor
/// BEFORE the config reaches `CircuitBuilder::new`.
///
/// Rejects, with a controlled error instead of a mid-build panic or an
/// exponential allocation:
/// - zero-valued knobs (`num_challenges`, `security_bits`,
///   `fri_config.num_query_rounds`) that plonky2 only trips over deep
///   inside construction or proving;
/// - structural floors of the pinned recursion stack
///   (`num_wires >= 135`, `37 <= num_routed_wires <= num_wires`,
///   `max_quotient_degree_factor >= 7`);
/// - FRI exponent ceilings (`rate_bits <= 8`, `cap_height <= 8`), both of
///   which drive `1 << x` work and memory;
/// - the rate/quotient consistency rule
///   (`rate_bits >= ceil(log2(max_quotient_degree_factor))`) that plonky2's
///   prover asserts only at proving time, after the full circuit build.
///
/// This is deliberately a STRUCTURAL policy, not a canonicality check:
/// profiling sweeps and tests legitimately build variant configs, and
/// canonicality of production artifacts is pinned at the artifact-load
/// boundaries. Every canonical `wormhole_*_circuit_config()` passes.
pub fn validate_circuit_config(config: &CircuitConfig) -> anyhow::Result<()> {
    use anyhow::ensure;

    for (name, value) in [
        ("num_challenges", config.num_challenges),
        ("security_bits", config.security_bits),
        (
            "fri_config.num_query_rounds",
            config.fri_config.num_query_rounds,
        ),
    ] {
        ensure!(value > 0, "circuit config {} must be greater than 0", name);
    }

    ensure!(
        config.num_wires >= MIN_NUM_WIRES,
        "circuit config num_wires ({}) must be >= {} (Poseidon gate floor)",
        config.num_wires,
        MIN_NUM_WIRES,
    );
    ensure!(
        config.num_routed_wires >= MIN_NUM_ROUTED_WIRES,
        "circuit config num_routed_wires ({}) must be >= {} (recursion gate floor: the FRI \
         coset-interpolation gate routes 37 wires, and narrower widths leave slot-packed gates \
         with zero operation slots)",
        config.num_routed_wires,
        MIN_NUM_ROUTED_WIRES,
    );
    ensure!(
        config.num_routed_wires <= config.num_wires,
        "circuit config num_routed_wires ({}) must be <= num_wires ({}); routed wires are a \
         prefix of the wire columns",
        config.num_routed_wires,
        config.num_wires,
    );
    ensure!(
        config.max_quotient_degree_factor >= MIN_MAX_QUOTIENT_DEGREE_FACTOR,
        "circuit config max_quotient_degree_factor ({}) must be >= {} (Poseidon constraint \
         degree)",
        config.max_quotient_degree_factor,
        MIN_MAX_QUOTIENT_DEGREE_FACTOR,
    );
    ensure!(
        config.fri_config.rate_bits <= MAX_RATE_BITS,
        "circuit config fri_config.rate_bits ({}) must be <= {} (LDE memory doubles per bit: \
         lde_size = 2^(degree_bits + rate_bits) per committed polynomial)",
        config.fri_config.rate_bits,
        MAX_RATE_BITS,
    );
    ensure!(
        config.fri_config.cap_height <= MAX_CAP_HEIGHT,
        "circuit config fri_config.cap_height ({}) must be <= {} (Merkle caps and recursive \
         verifier-data allocations scale as 2^cap_height)",
        config.fri_config.cap_height,
        MAX_CAP_HEIGHT,
    );

    // Plonky2's prover asserts `ceil(log2(quotient_degree_factor)) <=
    // rate_bits` only at proving time, after the full circuit build; reject
    // the doomed pair up front. With the quotient floor of 7 (bits = 3) this
    // also means rate_bits below 3 can never prove.
    let quotient_degree_bits = log2_ceil(config.max_quotient_degree_factor);
    ensure!(
        config.fri_config.rate_bits >= quotient_degree_bits,
        "circuit config fri_config.rate_bits ({}) must be >= \
         ceil(log2(max_quotient_degree_factor = {})) = {}; plonky2's prover cannot compute \
         quotient chunks of degree higher than the FRI rate and asserts this only at proving \
         time, after the full circuit build",
        config.fri_config.rate_bits,
        config.max_quotient_degree_factor,
        quotient_degree_bits,
    );

    Ok(())
}

pub trait CircuitFragment {
    /// The targets that the circuit operates on. These are constrained in the circuit definition
    /// and filled with [`Self::fill_targets`].
    type Targets;

    /// Builds a circuit with the operating wires being provided by [`Self::Targets`].
    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>);

    /// Fills the targets in the partial witness with the provided inputs.
    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()>;
}

#[cfg(test)]
mod validate_circuit_config_tests {
    use super::*;

    #[test]
    fn canonical_wormhole_configs_pass() {
        validate_circuit_config(&wormhole_leaf_circuit_config()).unwrap();
        validate_circuit_config(&wormhole_private_batch_circuit_config()).unwrap();
        validate_circuit_config(&wormhole_public_batch_circuit_config()).unwrap();
        validate_circuit_config(&CircuitConfig::standard_recursion_config()).unwrap();
        validate_circuit_config(&CircuitConfig::standard_recursion_zk_config()).unwrap();
    }

    #[test]
    fn structural_floors_are_enforced() {
        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.num_wires = MIN_NUM_WIRES - 1;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("num_wires"), "got: {err}");

        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.num_routed_wires = MIN_NUM_ROUTED_WIRES - 1;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("num_routed_wires"), "got: {err}");

        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.num_routed_wires = cfg.num_wires + 1;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("prefix"), "got: {err}");

        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.max_quotient_degree_factor = MIN_MAX_QUOTIENT_DEGREE_FACTOR - 1;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("max_quotient_degree_factor"),
            "got: {err}"
        );
    }

    #[test]
    fn fri_exponent_ceilings_are_enforced() {
        for bits in [MAX_RATE_BITS + 1, 20, 63, usize::MAX] {
            let mut cfg = wormhole_private_batch_circuit_config();
            cfg.fri_config.rate_bits = bits;
            let err = validate_circuit_config(&cfg).unwrap_err();
            assert!(err.to_string().contains("rate_bits"), "got: {err}");

            let mut cfg = wormhole_private_batch_circuit_config();
            cfg.fri_config.cap_height = bits;
            let err = validate_circuit_config(&cfg).unwrap_err();
            assert!(err.to_string().contains("cap_height"), "got: {err}");
        }
        // The ceilings themselves pass.
        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.fri_config.rate_bits = MAX_RATE_BITS;
        cfg.fri_config.cap_height = MAX_CAP_HEIGHT;
        validate_circuit_config(&cfg).unwrap();
    }

    #[test]
    fn rate_bits_below_quotient_degree_are_rejected() {
        for bits in [1, 2] {
            let mut cfg = wormhole_private_batch_circuit_config();
            cfg.fri_config.rate_bits = bits;
            let err = validate_circuit_config(&cfg).unwrap_err();
            assert!(err.to_string().contains("proving time"), "got: {err}");
        }
    }

    #[test]
    fn zero_knobs_are_rejected() {
        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.num_challenges = 0;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("num_challenges"), "got: {err}");

        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.fri_config.num_query_rounds = 0;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("num_query_rounds"), "got: {err}");

        let mut cfg = wormhole_private_batch_circuit_config();
        cfg.security_bits = 0;
        let err = validate_circuit_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("security_bits"), "got: {err}");
    }
}

#[cfg(test)]
mod transfer_proof_json_tests {
    use super::*;

    #[test]
    fn storage_proof_deserialization_rejects_oversized_node() {
        let oversized = "a".repeat(MAX_STORAGE_PROOF_NODE_HEX_LEN + 1);
        let json = format!(
            r#"{{"transfer_count":1,"state_root":"00","storage_proof":["{}"],"indices":[]}}"#,
            oversized
        );
        let err = TransferProofJson::from_json_str(&json).unwrap_err();
        assert!(err.contains("storage_proof node exceeds"));
    }

    /// A single field written as JSON escape sequences forces serde_json to
    /// decode the whole thing into scratch storage BEFORE the visitor's field
    /// bound can observe its length. The raw payload cap must therefore reject
    /// oversized documents up front, without ever handing them to serde.
    #[test]
    fn oversized_escaped_payload_is_rejected_by_the_raw_size_cap() {
        // An escaped state_root that decodes to megabytes: each `\u0061` is one
        // decoded byte, so the field bound (64 bytes) only fires after the
        // deserializer has already buffered the full decoded string.
        let escaped = "\\u0061".repeat(MAX_TRANSFER_PROOF_JSON_BYTES / 6 + 1);
        let json = format!(
            r#"{{"transfer_count":1,"state_root":"{}","storage_proof":[],"indices":[]}}"#,
            escaped
        );
        let err = TransferProofJson::from_json_str(&json).unwrap_err();
        assert!(
            err.contains("transfer proof JSON exceeds"),
            "oversized payload must be rejected by the raw size cap before parsing, got: {err}"
        );
    }

    /// Escapes are legal JSON: a payload whose fields are within bounds must
    /// still parse even when its strings are escape-encoded.
    #[test]
    fn escaped_but_in_bounds_payload_still_parses() {
        let escaped_root = "\\u0061".repeat(8); // decodes to "aaaaaaaa"
        let json = format!(
            r#"{{"transfer_count":1,"state_root":"{}","storage_proof":["00"],"indices":[0]}}"#,
            escaped_root
        );
        let proof = TransferProofJson::from_json_str(&json).unwrap();
        assert_eq!(proof.state_root, "a".repeat(8));
    }

    /// Payloads under the raw cap must still hit the per-field bounds.
    #[test]
    fn in_cap_payload_with_oversized_state_root_is_rejected_by_field_bound() {
        let json = format!(
            r#"{{"transfer_count":1,"state_root":"{}","storage_proof":[],"indices":[]}}"#,
            "a".repeat(MAX_STATE_ROOT_HEX_LEN + 1)
        );
        let err = TransferProofJson::from_json_str(&json).unwrap_err();
        assert!(err.contains("state_root exceeds"), "got: {err}");
    }

    #[test]
    fn direct_validation_rejects_oversized_storage_proof_total() {
        let proof = TransferProofJson {
            transfer_count: 1,
            state_root: String::from("00"),
            storage_proof: vec![
                "a".repeat(MAX_STORAGE_PROOF_HEX_BYTES / 2 + 1),
                "b".repeat(MAX_STORAGE_PROOF_HEX_BYTES / 2 + 1),
            ],
            indices: vec![],
        };
        let err = proof.validate().unwrap_err();
        assert!(err.contains("total bytes"));
    }
}
