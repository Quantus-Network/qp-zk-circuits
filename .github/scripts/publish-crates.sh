#!/usr/bin/env bash
# Publish workspace crates to crates.io in dependency order.
# Strips local `path` keys and drops unpublished local-only / cyclic dev-deps.
# Already-published versions are skipped so a partial release can be resumed.
set -euo pipefail

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
	echo "CARGO_REGISTRY_TOKEN is required" >&2
	exit 1
fi

prepare_manifest() {
	local manifest=$1
	shift

	# Drop crates that are never published (or form a publish-time cycle)
	# *before* stripping `path`, so we never leave `{ package = "..." }`.
	local drop
	for drop in test-helpers wormhole-circuit-builder "$@"; do
		sed -i "/^${drop} = /d" "$manifest"
	done

	sed -i -E 's/,\s*path\s*=\s*"[^"]+"//g' "$manifest"
}

publish_dir() {
	local dir=$1
	echo "Publishing ${dir}"

	set +e
	cargo publish --allow-dirty --token "$CARGO_REGISTRY_TOKEN" --manifest-path "${dir}/Cargo.toml" 2>&1 | tee /tmp/cargo-publish.out
	local rc=${PIPESTATUS[0]}
	set -e

	if [[ "$rc" -eq 0 ]]; then
		echo "Waiting for crates.io to serve ${dir}"
		sleep 30
		return 0
	fi

	if grep -qiE 'already exists|already uploaded' /tmp/cargo-publish.out; then
		echo "Already on crates.io, skipping ${dir}"
		return 0
	fi

	return "$rc"
}

publish_dir proof

prepare_manifest common/Cargo.toml
publish_dir wormhole/inputs
publish_dir common

prepare_manifest wormhole/circuit/Cargo.toml
publish_dir wormhole/circuit

prepare_manifest wormhole/prover/Cargo.toml wormhole-aggregator
publish_dir wormhole/prover

prepare_manifest wormhole/verifier/Cargo.toml
publish_dir wormhole/verifier

prepare_manifest wormhole/aggregator/Cargo.toml
publish_dir wormhole/aggregator

prepare_manifest wormhole/circuit-builder/Cargo.toml
publish_dir wormhole/circuit-builder

prepare_manifest ownership/inputs/Cargo.toml
publish_dir ownership/inputs

prepare_manifest ownership/circuit/Cargo.toml
publish_dir ownership/circuit

prepare_manifest ownership/prover/Cargo.toml
publish_dir ownership/prover

prepare_manifest ownership/verifier/Cargo.toml
publish_dir ownership/verifier

prepare_manifest ownership/circuit-builder/Cargo.toml
publish_dir ownership/circuit-builder
