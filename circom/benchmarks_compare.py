#!/usr/bin/env python3
"""Pre-Nova (monolithic Groth16) vs Nova (step-chain IVC) benchmarks for
CardanoKeyOwnership (Ed25519) and CardanoKeyOwnershipSMT.

Times the end-to-end phases of both proving modes per circuit family and
prints a markdown comparison table:

  Pre-Nova (Impl 7): key+input -> mono witness -> ceremony -> prove -> verify
  Nova     (Impl 8): key+input -> 255 step witnesses -> ceremony -> fold -> verify

Ceremonies are one-time costs; step witnesses are per-input.  Measurements are
cached in <workdir>/bench_times.json (namespaced per family) so reused phases
still count toward the end-to-end totals.  Use --force to re-measure the
reusable phases (ceremonies, step-witness sets, circuit input, witness).

Usage:
    python3 benchmarks_compare.py --family cko --xsk pay.xsk --vk pay.vk
    python3 benchmarks_compare.py --family smt --xsk pay.xsk --vk pay.vk
    python3 benchmarks_compare.py --all --xsk pay.xsk --vk pay.vk [--force]
"""

import argparse
import json
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.join(SCRIPT_DIR, "../clis/groth16/target/release/groth16")
# Trusted-setup ceremonies moved to the standalone `trusted-setup` CLI
# (clis/trusted-setup); default to its release binary if present.
DEFAULT_TRUSTED_SETUP = os.path.join(SCRIPT_DIR,
                                     "../../clis/trusted-setup/target/release/trusted-setup")
if not os.path.exists(DEFAULT_TRUSTED_SETUP):
    DEFAULT_TRUSTED_SETUP = "trusted-setup"
# The SMT input generator shells out to the standalone `smt` CLI (clis/smt)
# for all SMT/Ed25519 crypto; default to its release binary if present.
DEFAULT_SMT_CLI = os.path.join(SCRIPT_DIR, "../../clis/smt/target/release/smt")
if not os.path.exists(DEFAULT_SMT_CLI):
    DEFAULT_SMT_CLI = "smt"

FAMILIES = {
    "cko": {
        "label": "CardanoKeyOwnership (Ed25519)",
        "dir": "CardanoKeyOwnership",
        "input_gen": ["python3", "gen_cardano_address_input.py"],
        "input_extra": [],
        "mono_wasm": "cardano_ed25519_ownership_js/cardano_ed25519_ownership.wasm",
        "mono_r1cs": "cardano_ed25519_ownership.r1cs",
        "nova_wasm": "cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm",
        "nova_r1cs": "cardano_ed25519_ownership_nova.r1cs",
        "mono_constraints": 1967405,
        "step_constraints": 7724,
        "steps": 255,
    },
    "smt": {
        "label": "CardanoKeyOwnershipSMT (Ed25519 + SMT)",
        "dir": "CardanoKeyOwnershipSMT",
        "input_gen": ["python3", "gen_smt_input.py"],
        "input_extra": ["--depth", "4"],
        "mono_wasm": "cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm",
        "mono_r1cs": "cardano_key_ownership_smt.r1cs",
        "nova_wasm": "cardano_key_ownership_smt_nova_js/cardano_key_ownership_smt_nova.wasm",
        "nova_r1cs": "cardano_key_ownership_smt_nova.r1cs",
        "mono_constraints": 1971079,
        "step_constraints": 7724,
        "steps": 255,
    },
}


def run_timed(cmd, cwd=None):
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    dt = time.perf_counter() - t0
    if r.returncode != 0:
        print(f"    FAILED: {' '.join(cmd)}\n{r.stderr[-800:]}", file=sys.stderr)
        sys.exit(1)
    return dt


def phase(store, key, cmd, reused, cwd=None):
    if reused:
        prev = store.get(key)
        print(f"    {key}: reused ({prev:.1f}s)" if prev else f"    {key}: reused")
        return
    dt = run_timed(cmd, cwd=cwd)
    store[key] = dt
    print(f"    {key}: {dt:.1f}s")


def fmt_size(path):
    if not path or not os.path.exists(path):
        return "n/a"
    n = float(os.path.getsize(path))
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_sec(v):
    return f"{v:.1f}s" if v is not None else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", choices=["cko", "smt", "all"], default="all")
    ap.add_argument("--workdir", default="/tmp/opencode/bench")
    ap.add_argument("--xsk")
    ap.add_argument("--vk")
    ap.add_argument("--bin", default=DEFAULT_BIN)
    ap.add_argument("--trusted-setup", default=DEFAULT_TRUSTED_SETUP,
                    help="Path to the standalone 'trusted-setup' CLI "
                         "(clis/trusted-setup) used for the monolithic ceremony.")
    ap.add_argument("--smt-cli", default=DEFAULT_SMT_CLI,
                    help="Path to the standalone 'smt' CLI (clis/smt) used for "
                         "SMT/Ed25519 crypto in the CardanoKeyOwnershipSMT family.")
    ap.add_argument("--snarkjs", default="snarkjs")
    ap.add_argument("--cardano-address", default="cardano-address")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-run", action="store_true",
                    help="print the table from cached timings only (no measurement)")
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    times_path = os.path.join(args.workdir, "bench_times.json")
    store = json.load(open(times_path)) if os.path.exists(times_path) else {}

    fams = ["cko", "smt"] if args.family == "all" else [args.family]
    for fname in fams:
        fam = FAMILIES[fname]
        fdir = os.path.join(SCRIPT_DIR, fam["dir"])
        print(f"\n## {fam['label']} ({fam['mono_constraints']:,} constraints "
              f"monolithic / {fam['steps']} × {fam['step_constraints']:,} constraints steps)")
        print()

        pay_xsk = args.xsk or os.path.join(args.workdir, "pay.xsk")
        pay_vk = args.vk or os.path.join(args.workdir, "pay.vk")

        if args.no_run:
            json.dump(store, open(times_path, "w"), indent=2)
            _print_table(args, fname, fam, store)
            continue

        if not (os.path.exists(pay_xsk) and os.path.exists(pay_vk)):
            t0 = time.perf_counter()
            phrase = os.path.join(args.workdir, "phrase.prv")
            root = os.path.join(args.workdir, "root.xsk")
            with open(phrase, "w") as f:
                subprocess.run([args.cardano_address, "recovery-phrase", "generate",
                                "--size", "15"], check=True, capture_output=True, stdout=f)
            with open(phrase) as f, open(root, "w") as o:
                subprocess.run([args.cardano_address, "key", "from-recovery-phrase",
                                "Shelley"], check=True, stdin=f, capture_output=True, stdout=o)
            with open(root) as f, open(pay_xsk, "w") as o:
                subprocess.run([args.cardano_address, "key", "child", "1852H/1815H/0H/0/0"],
                               check=True, stdin=f, capture_output=True, stdout=o)
            with open(pay_xsk) as f, open(pay_vk, "w") as o:
                subprocess.run([args.cardano_address, "key", "public",
                                "--without-chain-code"], check=True, stdin=f,
                               capture_output=True, stdout=o)
            store[f"{fname}_key_derivation"] = time.perf_counter() - t0
            print(f"    key derivation: {store[f'{fname}_key_derivation']:.1f}s")
        else:
            print("    key derivation: reused")

        input_json = os.path.join(args.workdir, f"{fname}_input.json")
        if os.path.exists(input_json) and not args.force:
            print("    circuit input: reused")
        else:
            # The SMT input generator shells out to the standalone `smt` CLI
            # for all crypto.
            input_cmd = fam["input_gen"] + ["--xsk", pay_xsk, "--vk", pay_vk,
                                            "-o", input_json] + fam["input_extra"]
            if fname == "smt":
                input_cmd += ["--smt-cli", args.smt_cli]
            dt = run_timed(input_cmd, cwd=fdir)
            store[f"{fname}_input"] = dt
            print(f"    circuit input: {dt:.1f}s")

        mono_wasm = os.path.join(fdir, fam["mono_wasm"])
        mono_r1cs = os.path.join(fdir, fam["mono_r1cs"])
        mono_wtns = os.path.join(args.workdir, f"{fname}_witness.wtns")
        mono_pk = os.path.join(args.workdir, f"{fname}.pk")
        mono_vk = os.path.join(args.workdir, f"{fname}.vk")
        mono_proof = os.path.join(args.workdir, f"{fname}_proof.bin")
        mono_pub = os.path.join(args.workdir, f"{fname}_proof.pub")
        steps_dir = os.path.join(args.workdir, f"{fname}_steps")
        nova_pk = os.path.join(args.workdir, f"{fname}_nova.pk")
        nova_vk = os.path.join(args.workdir, f"{fname}_nova.vk")
        ivc = os.path.join(args.workdir, f"{fname}_ivc.json")

        print("  PRE-NOVA (monolithic)")
        phase(store, f"{fname}_mono_witness",
              [args.snarkjs, "wc", mono_wasm, input_json, mono_wtns],
              os.path.exists(mono_wtns) and not args.force)
        phase(store, f"{fname}_mono_ceremony",
              [args.trusted_setup, "ceremony-dev", "--sparse", "--h-scalar",
               "--circuit", mono_r1cs, "--proving-key", mono_pk,
               "--verifying-key", mono_vk],
              os.path.exists(mono_pk) and os.path.exists(mono_vk) and not args.force)
        phase(store, f"{fname}_mono_prove",
              [args.bin, "prove", "--sparse", "--circuit", mono_r1cs,
               "--witness", mono_wtns, "--proving-key", mono_pk, "--out", mono_proof],
              False)
        phase(store, f"{fname}_mono_verify",
              [args.bin, "verify", "--proof", mono_proof, "--public", mono_pub,
               "--verifying-key", mono_vk],
              False)

        print("  NOVA (step-chain)")
        nova_r1cs = os.path.join(fdir, fam["nova_r1cs"])
        step0 = os.path.join(steps_dir, "step_0000.wtns")
        phase(store, f"{fname}_nova_steps",
              ["python3", os.path.join(SCRIPT_DIR, "CardanoKeyOwnershipSMT",
                                       "gen_smt_nova_steps.py"),
               "--input", input_json, "--wasm", os.path.join(fdir, fam["nova_wasm"]),
               "--dir", steps_dir, "--snarkjs", args.snarkjs],
              os.path.exists(step0) and not args.force)
        phase(store, f"{fname}_nova_ceremony",
              [args.bin, "nova", "ceremony", "--circuit", nova_r1cs,
               "--proving-key", nova_pk, "--verifying-key", nova_vk],
              os.path.exists(nova_pk) and os.path.exists(nova_vk) and not args.force)
        phase(store, f"{fname}_nova_fold",
              [args.bin, "nova", "fold", "--circuit", nova_r1cs,
               "--proving-key", nova_pk, "--steps", steps_dir, "--out", ivc],
              False)
        phase(store, f"{fname}_nova_verify",
              [args.bin, "nova", "verify", "--ivc", ivc, "--verifying-key", nova_vk],
              False)

        json.dump(store, open(times_path, "w"), indent=2)
        _print_table(args, fname, fam, store)


def _print_table(args, fname, fam, store):
    workdir = args.workdir
    s = lambda k: store.get(f"{fname}_{k}")
    key = s("input") or 0.0
    mono_first = key + sum(s(k) or 0 for k in
                           ("mono_witness", "mono_ceremony", "mono_prove", "mono_verify"))
    mono_steady = key + sum(s(k) or 0 for k in
                            ("mono_witness", "mono_prove", "mono_verify"))
    nova_first = key + sum(s(k) or 0 for k in
                           ("nova_steps", "nova_ceremony", "nova_fold", "nova_verify"))
    nova_steady = key + sum(s(k) or 0 for k in
                            ("nova_steps", "nova_fold", "nova_verify"))
    mono_pk = os.path.join(workdir, f"{fname}.pk")
    mono_vk = os.path.join(workdir, f"{fname}.vk")
    nova_pk = os.path.join(workdir, f"{fname}_nova.pk")
    nova_vk = os.path.join(workdir, f"{fname}_nova.vk")

    print(f"\n  | Phase | Pre-Nova (monolithic) | Nova (step-chain) |")
    print(f"  |---|---|---|")
    print(f"  | key + circuit input | shared: {fmt_sec(key)} | shared: {fmt_sec(key)} |")
    print(f"  | witness generation | {fmt_sec(s('mono_witness'))} | 255 steps: {fmt_sec(s('nova_steps'))} |")
    print(f"  | ceremony (one-time) | {fmt_sec(s('mono_ceremony'))} | {fmt_sec(s('nova_ceremony'))} |")
    print(f"  | prove / fold | {fmt_sec(s('mono_prove'))} | {fmt_sec(s('nova_fold'))} |")
    print(f"  | verify | {fmt_sec(s('mono_verify'))} | {fmt_sec(s('nova_verify'))} |")
    print(f"  | **e2e, first run (incl. ceremony)** | **{fmt_sec(mono_first)}** | **{fmt_sec(nova_first)}** |")
    print(f"  | **e2e, steady (ceremony amortized)** | **{fmt_sec(mono_steady)}** | **{fmt_sec(nova_steady)}** |")
    print(f"  | proving key size | {fmt_size(mono_pk)} | {fmt_size(nova_pk)} |")
    print(f"  | verifying key size | {fmt_size(mono_vk)} | {fmt_size(nova_vk)} |")


if __name__ == "__main__":
    main()
