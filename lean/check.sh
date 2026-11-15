#!/usr/bin/env bash
# Check the Lean proofs with an official Lean toolchain, and regenerate the Rust differential
# vectors from the Lean definitions: ./check.sh [path/to/lean]
set -euo pipefail
cd "$(dirname "$0")"
L=${1:-lean}
LIB=$(dirname "$(dirname "$(command -v "$L" || echo "$L")")")/lib/lean
"$L" -o Merkle.olean Merkle.lean
LEAN_PATH="$LIB:." "$L" -o Store.olean Store.lean
LEAN_PATH="$LIB:." "$L" Tests.lean
LEAN_PATH="$LIB:." "$L" Axioms.lean | tee axioms.out
! grep -q sorryAx axioms.out
LEAN_PATH="$LIB:." "$L" -o Sha256.olean Sha256.lean
LEAN_PATH="$LIB:." "$L" --run Vectors.lean vectors.out 32
cmp -s vectors.out ../crates/vesdb-core/tests/lean_vectors.json \
  || { echo "lean_vectors.json is stale: copy lean/vectors.out over it"; exit 1; }
echo "LEAN: consistency_sound, receipt_binding proved; VesdbStore no_fork, views_prefix, ack_durable, receipt_sound, idempotent, redaction_keeps_proofs proved; tests pass; Rust vectors match Lean"
