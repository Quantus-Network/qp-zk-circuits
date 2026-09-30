//! Records the leaf circuit's gadget calls and constraint system for the Lean constraint
//! exporter (`qp-plonky2/constraint-exporter`, PLAN.md Step 9) and checks the trace
//! `formal/traces/leaf_circuit.json` is current. Regenerate with
//! `UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-circuit --test formal_trace`.

use plonky2::iop::target::Target;
use qp_wormhole_circuit::circuit::circuit_logic::{build_leaf_constraints, CircuitTargets};
use zk_circuits_common::{
    circuit::wormhole_leaf_circuit_config,
    formal_trace::{Trace, TracingBuilder},
};

#[test]
fn leaf_circuit_trace_is_current() {
    let mut tracing = TracingBuilder::new(wormhole_leaf_circuit_config());
    let targets = CircuitTargets::new(&mut tracing);
    build_leaf_constraints(&targets, &mut tracing);

    let hash = |h: &plonky2::hash::hash_types::HashOutTarget| h.elements.to_vec();
    let mut named: Vec<(String, Vec<Target>)> = vec![
        ("secret".into(), hash(&targets.nullifier.secret)),
        (
            "transfer_count".into(),
            targets.nullifier.transfer_count.to_vec(),
        ),
        (
            "to_account".into(),
            targets.zk_merkle_proof.leaf.to_account.to_vec(),
        ),
        (
            "account_id".into(),
            hash(&targets.unspendable_account.account_id),
        ),
        ("root_hash".into(), hash(&targets.zk_merkle_proof.root_hash)),
        ("depth".into(), vec![targets.zk_merkle_proof.depth]),
        (
            "positions".into(),
            targets.zk_merkle_proof.positions.clone(),
        ),
        (
            "is_not_dummy".into(),
            vec![targets.zk_merkle_proof.is_not_dummy.target],
        ),
    ];
    for (level, siblings) in targets.zk_merkle_proof.siblings.iter().enumerate() {
        named.push((
            format!("siblings_{level}"),
            siblings.iter().flat_map(hash).collect(),
        ));
    }
    let header = &targets.block_header.header;
    named.push(("header_parent_hash".into(), header.parent_hash.to_vec()));
    named.push(("header_state_root".into(), header.state_root.to_vec()));
    named.push((
        "header_extrinsics_root".into(),
        header.extrinsics_root.to_vec(),
    ));
    named.push(("header_zk_tree_root".into(), header.zk_tree_root.to_vec()));
    named.push(("header_digest".into(), header.digest.to_vec()));

    let trace = tracing.trace("leaf_circuit", named);
    let json = trace.to_json();
    let round_trip = Trace::from_json(&json).expect("trace round-trips");
    assert_eq!(round_trip.to_json(), json);
    println!(
        "leaf trace: rows={} copies={} calls={} public_inputs={}",
        trace.rows.len(),
        trace.copies.len(),
        trace.calls.len(),
        trace.public_inputs.len()
    );

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../formal/traces/leaf_circuit.json");
    if std::env::var_os("UPDATE_FORMAL_TRACE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &json).unwrap();
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        checked_in == json,
        "formal/traces/leaf_circuit.json is stale; regenerate with \
         UPDATE_FORMAL_TRACE=1 cargo test -p qp-wormhole-circuit --test formal_trace"
    );
}
