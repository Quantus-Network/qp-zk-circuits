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

#[derive(Debug, Deserialize)]
pub struct TransferProofJson {
    pub transfer_count: u64,
    #[serde(deserialize_with = "deserialize_bounded_state_root")]
    pub state_root: String, // hex (no 0x)
    #[serde(deserialize_with = "deserialize_bounded_storage_proof")]
    pub storage_proof: Vec<String>, // hex-encoded nodes
    #[serde(deserialize_with = "deserialize_bounded_indices")]
    pub indices: Vec<usize>,
}

impl TransferProofJson {
    /// Parse untrusted transfer-proof JSON, bounding allocation up front.
    ///
    /// This is the entry point services should use for attacker-supplied
    /// payloads. The raw document length is checked against
    /// [`MAX_TRANSFER_PROOF_JSON_BYTES`] BEFORE any parsing: the per-field
    /// Serde bounds only observe string lengths after the deserializer has
    /// decoded escaped content into scratch storage, so on their own they
    /// cannot stop a single escape-inflated field from allocating and
    /// scanning arbitrarily far past its cap before being rejected.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        if json.len() > MAX_TRANSFER_PROOF_JSON_BYTES {
            return Err(format!(
                "transfer proof JSON exceeds {} bytes ({} bytes); refusing to parse it",
                MAX_TRANSFER_PROOF_JSON_BYTES,
                json.len()
            ));
        }
        serde_json::from_str(json).map_err(|e| format!("failed to parse transfer proof JSON: {e}"))
    }

    /// Validate the decoded transfer proof bounds.
    ///
    /// `#[serde(deserialize_with)]` enforces the same caps on parsed documents
    /// (though only after the deserializer has decoded each string — see
    /// [`Self::from_json_str`] for the raw-input bound); this is a convenience
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
/// this bound alone does not cap allocation. [`TransferProofJson::from_json_str`]
/// bounds the raw document first; use it for untrusted payloads.
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
mod transfer_proof_json_tests {
    use super::*;

    #[test]
    fn storage_proof_deserialization_rejects_oversized_node() {
        let oversized = "a".repeat(MAX_STORAGE_PROOF_NODE_HEX_LEN + 1);
        let json = format!(
            r#"{{"transfer_count":1,"state_root":"00","storage_proof":["{}"],"indices":[]}}"#,
            oversized
        );
        let err = serde_json::from_str::<TransferProofJson>(&json).unwrap_err();
        assert!(err.to_string().contains("storage_proof node exceeds"));
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
