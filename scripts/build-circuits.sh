#!/usr/bin/env bash
#
# Build circuit binaries for the wormhole prover/verifier.
#
# Usage:
#   ./scripts/build-circuits.sh [NUM_LEAF_PROOFS] [NUM_EXIT_SLOTS]
#
# Arguments:
#   NUM_LEAF_PROOFS - Number of leaf proofs per private-batch aggregation (default: 10)
#   NUM_EXIT_SLOTS  - Number of withdrawal output slots per private batch (default: 32)
#
# The defaults are the production shape (`qp_wormhole_inputs::production`).
#
# Output:
#   Circuit binaries are written to wormhole/generated-bins/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_LEAF_PROOFS="${1:-10}"
NUM_EXIT_SLOTS="${2:-32}"
OUTPUT_DIR="$REPO_ROOT/wormhole/generated-bins"

echo "Building circuit binaries (num_leaf_proofs=$NUM_LEAF_PROOFS, num_exit_slots=$NUM_EXIT_SLOTS)..."
echo "Output directory: $OUTPUT_DIR"

cargo run --release -p qp-wormhole-circuit-builder -- \
    --num-leaf-proofs "$NUM_LEAF_PROOFS" \
    --num-exit-slots "$NUM_EXIT_SLOTS" \
    --output "$OUTPUT_DIR"

echo "Done! Circuit binaries written to $OUTPUT_DIR"
