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
/// Maximum number of Merkle indices accepted in [`TransferProofJson`].
pub const MAX_MERKLE_INDICES: usize = 1024;
/// Maximum byte length of the hex `state_root` string in [`TransferProofJson`].
pub const MAX_STATE_ROOT_HEX_LEN: usize = 64;

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
    /// Validate the decoded transfer proof bounds.
    ///
    /// `#[serde(deserialize_with)]` already caps each field at deserialization time;
    /// this is a convenience check for callers that construct the struct directly.
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
        if self.indices.len() > MAX_MERKLE_INDICES {
            return Err(format!("indices exceeds {} entries", MAX_MERKLE_INDICES));
        }
        Ok(())
    }
}

/// Deserialize a hex `state_root` string, rejecting inputs longer than
/// [`MAX_STATE_ROOT_HEX_LEN`] before allocating the owned `String`.
fn deserialize_bounded_state_root<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct StateRootVisitor;
    impl<'de> Visitor<'de> for StateRootVisitor {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a hex state_root string of at most {} bytes", MAX_STATE_ROOT_HEX_LEN)
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
            write!(f, "a sequence of at most {} items ({})", self.max, self.label)
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
    deserialize_bounded_vec(deserializer, MAX_STORAGE_PROOF_NODES, "storage_proof")
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
