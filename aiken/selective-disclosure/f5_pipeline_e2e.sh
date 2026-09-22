#!/usr/bin/env bash
#
# F5 Pipeline — selective-disclosure end-to-end
#
# Demonstrates the full selective-disclosure stack, with F5 (multi-user batch
# privacy pool) as the scale-up of Step 3:
#
#   Step 1  — Predicate proof (credential eligibility: age >= 21, etc.)
#   Step 2  — Twisted ElGamal (confidential amount hiding)
#   Step 3  — F5 multi-user privacy pool (batch spend, N proofs → 1 check)
#
# Each step is a self-contained Groth16 e2e.  The pipeline runs them in
# sequence and prints a narrative showing how they compose.
#
# Optional Step 4 (auditor reveal, amount only) can be enabled with WITH_AUDITOR=1.
# Optional Step 6 (multi-user batch + full audit) can be enabled with STEP6=1.
#
# Usage:
#   ./f5_pipeline_e2e.sh
#   USERS=8 WITH_AUDITOR=1 ./f5_pipeline_e2e.sh
#   USERS=8 STEP6=1 ./f5_pipeline_e2e.sh
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../.." && pwd)"

OUT="${OUT:-/tmp/sd_pipeline}"
USERS="${USERS:-4}"
SPENDS="${SPENDS:-$USERS}"
DEPTH="${DEPTH:-4}"
SEED="${SEED:-42}"
WITH_AUDITOR="${WITH_AUDITOR:-0}"

mkdir -p "$OUT"

echo "========================================================================"
echo "  F5 Pipeline — selective-disclosure end-to-end"
echo "========================================================================"
echo ""
echo "  Steps: 1 (predicate) → 2 (ElGamal) → 3 (F5 batch pool) → optional 4/6 (audit)"
echo "  Users : $USERS  |  Depth: $DEPTH  |  Seed: $SEED"
echo "  Output: $OUT"
echo ""

# ---------------------------------------------------------------------------
# Step 1 — Predicate proof (single holder demonstrates eligibility)
# ---------------------------------------------------------------------------
echo "== Step 1 | Predicate proof (credential eligibility) =="
STEP1_OUT="$OUT/step1"
mkdir -p "$STEP1_OUT"
# The step1 e2e writes to /tmp/sd_step1_groth16 by default; override OUT.
OUT="$STEP1_OUT" bash "$SDIR/step1/groth16_e2e.sh" >/dev/null 2>&1 || {
  echo "   Step 1 failed — check $STEP1_OUT"
  exit 1
}
echo "   proof     : $STEP1_OUT/predicate.proof"
echo "   public    : $STEP1_OUT/predicate.pub"
echo "   aiken vk  : $STEP1_OUT/predicate_vk.ak"
echo ""

# ---------------------------------------------------------------------------
# Step 2 — Twisted ElGamal (confidential amount)
# ---------------------------------------------------------------------------
echo "== Step 2 | Twisted ElGamal (confidential amount hiding) =="
STEP2_OUT="$OUT/step2"
mkdir -p "$STEP2_OUT"
OUT="$STEP2_OUT" bash "$SDIR/step2/groth16_e2e.sh" >/dev/null 2>&1 || {
  echo "   Step 2 failed — check $STEP2_OUT"
  exit 1
}
echo "   proof     : $STEP2_OUT/transfer.proof"
echo "   public    : $STEP2_OUT/transfer.pub"
echo "   aiken vk  : $STEP2_OUT/transfer_vk.ak"
echo ""

# ---------------------------------------------------------------------------
# Step 3 — F5 multi-user privacy pool (batch verification)
# ---------------------------------------------------------------------------
echo "== Step 3 | F5 multi-user privacy pool (batch spend) =="
STEP3_OUT="$OUT/step3"
mkdir -p "$STEP3_OUT"
OUT="$STEP3_OUT" USERS="$USERS" SPENDS="$SPENDS" DEPTH="$DEPTH" SEED="$SEED" \
  bash "$ROOT/aiken/f5/demo/f5_e2e_groth16.sh" || {
  echo "   Step 3 failed — check $STEP3_OUT"
  exit 1
}
echo "   proofs    : $(ls "$STEP3_OUT"/user_*.proof 2>/dev/null | wc -l)  (192 bytes each)"
echo "   scenario  : $STEP3_OUT/scenario.json"
echo "   timings   : $STEP3_OUT/timings.tsv"
echo ""

# ---------------------------------------------------------------------------
# Optional Step 4 — Auditor reveal (amount only)
# ---------------------------------------------------------------------------
if [ "$WITH_AUDITOR" -eq 1 ]; then
  echo "== Step 4 | Compliant shielded transfer (auditor reveal) =="
  STEP4_OUT="$OUT/step4"
  mkdir -p "$STEP4_OUT"
  OUT="$STEP4_OUT" bash "$SDIR/step4/groth16_e2e.sh" >/dev/null 2>&1 || {
    echo "   Step 4 failed — check $STEP4_OUT"
    exit 1
  }
  echo "   proof     : $STEP4_OUT/privacy_pool_viewable.proof"
  echo "   aiken vk  : $STEP4_OUT/pp_vk.ak"
  echo ""
fi

# ---------------------------------------------------------------------------
# Optional Step 6 — Multi-user batch + full auditor reveal
# ---------------------------------------------------------------------------
STEP6="${STEP6:-0}"
if [ "$STEP6" -eq 1 ]; then
  echo "== Step 6 | Multi-user batch pool + full auditor reveal =="
  STEP6_OUT="$OUT/step6"
  mkdir -p "$STEP6_OUT"
  OUT="$STEP6_OUT" USERS="$USERS" SPENDS="$SPENDS" DEPTH="$DEPTH" SEED="$SEED" \
    bash "$SDIR/step6/groth16_e2e.sh" || {
    echo "   Step 6 failed — check $STEP6_OUT"
    exit 1
  }
  echo "   proofs    : $(ls "$STEP6_OUT"/user_*.proof 2>/dev/null | wc -l)  (192 bytes each)"
  echo "   scenario  : $STEP6_OUT/scenario.json"
  echo "   timings   : $STEP6_OUT/timings.tsv"
  echo "   auditor   : $STEP6_OUT/auditor_meta.json"
  echo ""
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "========================================================================"
echo "  Pipeline complete"
echo "========================================================================"
echo ""
echo "  Step 1 (Predicate)   →  proves credential eligibility off-chain"
echo "  Step 2 (ElGamal)     →  hides the transfer amount off-chain"
echo "  Step 3 (F5 Pool)     →  N users batch-spend from a shared shielded pool"
echo "                          verified with ONE multi-pairing product"
if [ "$WITH_AUDITOR" -eq 1 ]; then
  echo "  Step 4 (Auditor)     →  amount encrypted to designated auditor PK"
fi
if [ "$STEP6" -eq 1 ]; then
  echo "  Step 6 (Batch+Audit) →  N users batch-spend + amount+address encrypted"
  echo "                          to auditor; verified in ONE batch check"
fi
echo ""
echo "  Artifacts:"
echo "    $OUT/step1/   — predicate proof + vk"
echo "    $OUT/step2/   — ElGamal transfer proof + vk"
echo "    $OUT/step3/   — F5 batch proofs + scenario + timings"
if [ "$WITH_AUDITOR" -eq 1 ]; then
  echo "    $OUT/step4/   — auditor-reveal proof + vk"
fi
if [ "$STEP6" -eq 1 ]; then
  echo "    $OUT/step6/   — batch-audit proofs + scenario + timings + auditor_meta"
fi
echo ""

# Print batch-verify speedup from Step 3 and Step 6 timings if available
print_speedup() {
  local tsv="$1" label="$2"
  if [ -f "$tsv" ]; then
    local v b r
    v=$(awk '$2=="verify" {t+=$3} END {printf "%.3f", t}' "$tsv")
    b=$(awk '$2=="batch-verify" {t+=$3} END {printf "%.3f", t}' "$tsv")
    if [ -n "$v" ] && [ -n "$b" ] && [ "$v" != "0.000" ]; then
      r=$(awk -v vv="$v" -v bb="$b" 'BEGIN {printf "%.1f", vv/bb}')
      echo "  Batch speedup ($label): ${v}s (individual) → ${b}s (batch) = ${r}×"
      echo ""
    fi
  fi
}
print_speedup "$STEP3_OUT/timings.tsv" "Step 3"
if [ "$STEP6" -eq 1 ]; then
  print_speedup "$STEP6_OUT/timings.tsv" "Step 6"
fi

echo "  Next: inspect proofs, paste .ak files into Aiken validators, or run"
echo "        'aiken check' in aiken/groth16 and aiken/f5/pool-contract."
echo ""
