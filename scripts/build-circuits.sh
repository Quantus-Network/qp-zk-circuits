#!/usr/bin/env bash
#
# Build circuit binaries for the wormhole prover/verifier.
#
# Usage:
#   ./scripts/build-circuits.sh [NUM_LEAF_PROOFS]
#
# Arguments:
#   NUM_LEAF_PROOFS - Number of leaf proofs per layer-0 aggregation (default: 16)
#
# Output:
#   Circuit binaries are written to wormhole/generated-bins/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_LEAF_PROOFS="${1:-16}"
OUTPUT_DIR="$REPO_ROOT/wormhole/generated-bins"

echo "Building circuit binaries (num_leaf_proofs=$NUM_LEAF_PROOFS)..."
echo "Output directory: $OUTPUT_DIR"

cargo run --release -p qp-wormhole-circuit-builder -- \
    --num-leaf-proofs "$NUM_LEAF_PROOFS" \
    --output "$OUTPUT_DIR"

echo "Done! Circuit binaries written to $OUTPUT_DIR"
