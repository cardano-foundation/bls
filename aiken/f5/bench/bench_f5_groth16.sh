#!/usr/bin/env bash
#
# F5 — benchmark: sweep pool users/transactions over the *current* Groth16
# pipeline (witness, dev ceremony, prove, verify, proof size, memory).
#
# Each config is driven through the standard e2e script (aiken/f5/demo/
# f5_e2e_groth16.sh) so numbers are produced by exactly the same code paths
# that the demo uses.  The only difference is the tree depth: we materialize a
# depth-varied circuit (gen_circuit_depth.py) so capacity fits the user count.
#
# Configs are "depth:users[:spends]" (spends defaults to users).
#   default: 4:1  6:4  6:8  6:16
#
# Output in $OUT_DIR:
#   results.tsv — aggregate rows (one per config/proof-count)
#   results.md  — markdown table for bench/README.md
#   <config>/* — full artifacts + timings.tsv per config
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
E2E="$ROOT/aiken/f5/demo/f5_e2e_groth16.sh"
GEN_CIRCUIT="$SDIR/gen_circuit_depth.py"

OUT_DIR="${OUT_DIR:-/tmp/f5_bench}"
CONFIGS="${CONFIGS:-4:1 6:4 6:8 6:16}"
SEED="${SEED:-42}"

mkdir -p "$OUT_DIR"
echo "== F5 benchmark | current Groth16 impl =="
echo "configs: $CONFIGS"

RESULTS="$OUT_DIR/results.tsv"
: > "$RESULTS"
echo -e "config\tusers\tspends\tdepth\tconstraints\tproof_bytes\twitness_total\twitness_maxrss\tceremony\tceremony_maxrss\tprove_total\tprove_maxrss\tverify_total\tverify_maxrss\tbatchverify_total\tbatchverify_maxrss\ttotal" >> "$RESULTS"

for cfg in $CONFIGS; do
  depth="${cfg%%:*}"
  rest="${cfg#*:}"
  users="${rest%%:*}"
  spends="${rest##*:}"
  [ -z "$spends" ] && spends="$users"

  cfg_out="$OUT_DIR/d${depth}_u${users}"
  circuit="$cfg_out/privacy_pool_d${depth}.circom"

  python3 "$GEN_CIRCUIT" --depth "$depth" --out "$circuit" --source "$PP/privacy_pool.circom"

  OUT="$cfg_out" DEPTH="$depth" USERS="$users" SPENDS="$spends" \
    SEED="$SEED" CIRCUIT="$circuit" bash "$E2E" > "$cfg_out/e2e.log" 2>&1

  # aggregate this config from its timings.tsv
  constraints="$(grep -oP 'constraints   : \K[0-9]+' "$cfg_out/e2e.log" | head -1)"
  proof_bytes="$(grep -oP '\(([0-9]+) bytes each\)' "$cfg_out/e2e.log" | grep -oP '[0-9]+')"
  T="$cfg_out/timings.tsv"
  wit_t="$(awk '$2=="witness"{s+=$3} END{printf "%.3f", s}' "$T")"
  wit_r="$(awk '$2=="witness"{if($4>m)m=$4} END{print m}' "$T")"
  cer_t="$(awk '$2=="ceremony"{s+=$3} END{printf "%.3f", s}' "$T")"
  cer_r="$(awk '$2=="ceremony"{if($4>m)m=$4} END{print m}' "$T")"
  prv_t="$(awk '$2=="prove"{s+=$3} END{printf "%.3f", s}' "$T")"
  prv_r="$(awk '$2=="prove"{if($4>m)m=$4} END{print m}' "$T")"
  vfy_t="$(awk '$2=="verify"{s+=$3} END{printf "%.3f", s}' "$T")"
  vfy_r="$(awk '$2=="verify"{if($4>m)m=$4} END{print m}' "$T")"
  bv_t="$(awk '$2=="batch-verify"{s+=$3} END{printf "%.3f", s}' "$T")"
  bv_r="$(awk '$2=="batch-verify"{if($4>m)m=$4} END{print m}' "$T")"
  total="$(awk '{s+=$3} END{printf "%.3f", s}' "$T")"

  echo -e "d${depth}_u${users}\t${users}\t${spends}\t${depth}\t${constraints}\t${proof_bytes}\t${wit_t}\t${wit_r}\t${cer_t}\t${cer_r}\t${prv_t}\t${prv_r}\t${vfy_t}\t${vfy_r}\t${bv_t}\t${bv_r}\t${total}" >> "$RESULTS"
  echo "  done d${depth}_u${users}: ${spends} proofs, ${proof_bytes}B each, total ${total}s"
done

# markdown rendering of the aggregate table
# columns: 1 config 2 users 3 spends 4 depth 5 constraints 6 proof(B)
#          7 witness 9 ceremony 11 prove 13 verify 15 batch-verify 17 total
MD="$OUT_DIR/results.md"
{
  echo "| config | users | spends | depth | constraints | proof (B) | witness | ceremony | prove | verify | batch-verify | speedup | total |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
  awk -F'\t' 'NR>1 {
    slow=$13; fast=$15;
    sp = (fast > 0) ? slow/fast : "-";
    sps = (sp != "-") ? sprintf("%.1fx", sp) : "-";
    printf "| %s | %s | %s | %s | %s | %s | %.1fs | %.1fs | %.1fs | %.1fs | %.1fs | %s | %.1fs |\n",
      $1, $2, $3, $4, $5, $6, $7, $9, $11, $13, $15, sps, $17
  }' "$RESULTS"
} > "$MD"

echo
echo "== results =="
sed -n '1,40p' "$RESULTS"
echo
echo "markdown table: $MD"