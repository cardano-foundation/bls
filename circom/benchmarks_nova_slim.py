#!/usr/bin/env python3
"""Competitive benchmark: BLS Groth16 / BLS Nova / upstream NovaSlim.

This script compares three proof systems on the same CardanoKeyOwnership
workload (Ed25519 scalar-mul decomposition, ~7,724 constraints/step, 255 steps):

  1. Monolithic Groth16 (BLS `groth16-prover` / `clis/trusted-setup`)
  2. In-tree Nova IVC (BLS `nova-prover` / `clis/nova`, Impl 9 and Impl 11)
  3. Upstream NovaSlim (`paweljakubas/nova-slim`, transparent sumcheck slim proofs)

It assumes the upstream `nova-slim` repository is checked out as a sibling of
this repository, i.e.:

    /home/pawel/Work/cardano-foundation/bls
    /home/pawel/Work/cardano-foundation/nova-slim

If your layout differs, pass `--nova-slim-dir <path>`.

Usage:
    python3 circom/benchmarks_nova_slim.py --family cko --steps 255
    python3 circom/benchmarks_nova_slim.py --family smt --steps 255
    python3 circom/benchmarks_nova_slim.py --all --steps 255

The script caches artifacts under <workdir> (default /tmp/opencode/bench_nova_slim)
so repeated runs only re-measure the variable phases.
"""

import argparse
import json
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BLS_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_NOVA_SLIM = os.path.join(BLS_DIR, "..", "nova-slim")

DEFAULT_BLS_GROTH16 = os.path.join(BLS_DIR, "clis", "groth16", "target", "release", "groth16")
DEFAULT_BLS_NOVA = os.path.join(BLS_DIR, "clis", "nova", "target", "release", "nova")
DEFAULT_BLS_TRUSTED_SETUP = os.path.join(BLS_DIR, "clis", "trusted-setup", "target", "release", "trusted-setup")
DEFAULT_SMT_CLI = os.path.join(BLS_DIR, "clis", "smt", "target", "release", "smt")

# ---------------------------------------------------------------------------
# Family definitions
# ---------------------------------------------------------------------------
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
        "default_steps": 255,
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
        "default_steps": 255,
    },
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def run_timed(cmd, cwd=None):
    """Run a command and return (elapsed_seconds, completed_process)."""
    print(f"  + {' '.join(map(str, cmd))}", flush=True)
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    dt = time.perf_counter() - t0
    if r.returncode != 0:
        print(f"    FAILED after {dt:.1f}s: {' '.join(map(str, cmd))}", file=sys.stderr)
        print(r.stderr[-1200:], file=sys.stderr)
        sys.exit(1)
    return dt, r


def run_logged(cmd, log_path, cwd=None):
    """Run a command logging stdout+stderr to log_path; returns elapsed seconds."""
    print(f"  + {' '.join(map(str, cmd))} > {log_path}", flush=True)
    t0 = time.perf_counter()
    with open(log_path, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True, cwd=cwd)
    dt = time.perf_counter() - t0
    if r.returncode != 0:
        print(f"    FAILED after {dt:.1f}s; see {log_path}", file=sys.stderr)
        sys.exit(1)
    return dt


def fmt_size(path):
    if not path or not os.path.exists(path):
        return "n/a"
    return fmt_bytes(os.path.getsize(path))


def fmt_bytes(n):
    if n is None:
        return "n/a"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def fmt_sec(v):
    return f"{v:.1f}s" if v is not None else "n/a"


def ensure_keypair(workdir, cardano_address="cardano-address"):
    pay_xsk = os.path.join(workdir, "pay.xsk")
    pay_vk = os.path.join(workdir, "pay.vk")
    if os.path.exists(pay_xsk) and os.path.exists(pay_vk):
        print("  keypair: reused")
        return pay_xsk, pay_vk
    print("  keypair: generating...")
    phrase = os.path.join(workdir, "phrase.prv")
    root = os.path.join(workdir, "root.xsk")
    with open(phrase, "w") as f:
        subprocess.run([cardano_address, "recovery-phrase", "generate", "--size", "15"],
                       check=True, stdout=f)
    with open(phrase) as f, open(root, "w") as o:
        subprocess.run([cardano_address, "key", "from-recovery-phrase", "Shelley"],
                       check=True, stdin=f, stdout=o)
    with open(root) as f, open(pay_xsk, "w") as o:
        subprocess.run([cardano_address, "key", "child", "1852H/1815H/0H/0/0"],
                       check=True, stdin=f, stdout=o)
    with open(pay_xsk) as f, open(pay_vk, "w") as o:
        subprocess.run([cardano_address, "key", "public", "--without-chain-code"],
                       check=True, stdin=f, stdout=o)
    print("  keypair: done")
    return pay_xsk, pay_vk


# ---------------------------------------------------------------------------
# Build helpers
# ---------------------------------------------------------------------------

def build_bls_binaries(args):
    print("\n[build] BLS groth16 CLI")
    run_logged(["cargo", "build", "--release"], os.path.join(args.workdir, "build_groth16.log"),
               cwd=os.path.join(BLS_DIR, "clis", "groth16"))
    print("[build] BLS nova CLI")
    run_logged(["cargo", "build", "--release"], os.path.join(args.workdir, "build_nova.log"),
               cwd=os.path.join(BLS_DIR, "clis", "nova"))
    print("[build] BLS trusted-setup CLI")
    run_logged(["cargo", "build", "--release"], os.path.join(args.workdir, "build_trusted_setup.log"),
               cwd=os.path.join(BLS_DIR, "clis", "trusted-setup"))
    if os.path.exists(os.path.join(BLS_DIR, "clis", "smt")):
        print("[build] BLS smt CLI")
        run_logged(["cargo", "build", "--release"], os.path.join(args.workdir, "build_smt.log"),
                   cwd=os.path.join(BLS_DIR, "clis", "smt"))


def build_nova_slim_binary(args):
    print("\n[build] NovaSlim benchmark_nova binary")
    manifest = os.path.join(args.nova_slim_dir, "prover", "Cargo.toml")
    if not os.path.exists(manifest):
        sys.exit(f"NovaSlim prover Cargo.toml not found: {manifest}")
    log = os.path.join(args.workdir, "build_nova_slim.log")
    # Build with all curve features so we can target bls12-381 (and others later).
    # Build only the BLS12-381 feature to keep compile times reasonable and to
    # avoid broken non-bls12-381 benchmark arms in the upstream binary.
    run_logged(["cargo", "build", "--release", "--manifest-path", manifest,
                "--features", "bls12-381",
                "--bin", "benchmark_nova"], log)
    bench_bin = os.path.join(args.nova_slim_dir, "prover", "target", "release", "benchmark_nova")
    if not os.path.exists(bench_bin):
        sys.exit(f"expected binary not found after build: {bench_bin}")
    return bench_bin


# ---------------------------------------------------------------------------
# BLS phases (reusing logic from benchmarks_compare.py)
# ---------------------------------------------------------------------------

def bls_generate_input(args, fname, fam, pay_xsk, pay_vk, store):
    fdir = os.path.join(SCRIPT_DIR, fam["dir"])
    input_json = os.path.join(args.workdir, f"{fname}_input.json")
    if os.path.exists(input_json) and not args.force:
        print("  circuit input: reused")
        return input_json
    input_cmd = fam["input_gen"] + ["--xsk", pay_xsk, "--vk", pay_vk, "-o", input_json] + fam["input_extra"]
    if fname == "smt":
        input_cmd += ["--smt-cli", args.smt_cli]
    dt, _ = run_timed(input_cmd, cwd=fdir)
    store[f"{fname}_input"] = dt
    print(f"  circuit input: {dt:.1f}s")
    return input_json


def bls_groth16_mono(args, fname, fam, input_json, store, store_path):
    fdir = os.path.join(SCRIPT_DIR, fam["dir"])
    mono_wasm = os.path.join(fdir, fam["mono_wasm"])
    mono_r1cs = os.path.join(fdir, fam["mono_r1cs"])
    mono_wtns = os.path.join(args.workdir, f"{fname}_witness.wtns")
    mono_pk = os.path.join(args.workdir, f"{fname}.pk")
    mono_vk = os.path.join(args.workdir, f"{fname}.vk")
    mono_proof = os.path.join(args.workdir, f"{fname}_proof.bin")
    mono_pub = os.path.join(args.workdir, f"{fname}_proof.pub")

    print("  GROTH16 (monolithic)")
    if os.path.exists(mono_wtns) and not args.force:
        print(f"    witness: reused")
    else:
        dt, _ = run_timed([args.snarkjs, "wc", mono_wasm, input_json, mono_wtns])
        store[f"{fname}_mono_witness"] = dt
        print(f"    witness: {dt:.1f}s")

    if os.path.exists(mono_pk) and os.path.exists(mono_vk) and not args.force:
        print("    ceremony: reused")
    else:
        dt, _ = run_timed([args.trusted_setup, "ceremony-dev", "--sparse", "--h-scalar",
                           "--circuit", mono_r1cs, "--proving-key", mono_pk,
                           "--verifying-key", mono_vk])
        store[f"{fname}_mono_ceremony"] = dt
        print(f"    ceremony: {dt:.1f}s")

    dt, _ = run_timed([args.groth16, "prove", "--sparse", "--circuit", mono_r1cs,
                       "--witness", mono_wtns, "--proving-key", mono_pk, "--out", mono_proof])
    store[f"{fname}_mono_prove"] = dt
    print(f"    prove: {dt:.1f}s")

    dt, _ = run_timed([args.groth16, "verify", "--proof", mono_proof, "--public", mono_pub,
                       "--verifying-key", mono_vk])
    store[f"{fname}_mono_verify"] = dt
    print(f"    verify: {dt:.1f}s")
    json.dump(store, open(store_path, "w"), indent=2)

    return {
        "pk_bytes": os.path.getsize(mono_pk) if os.path.exists(mono_pk) else None,
        "vk_bytes": os.path.getsize(mono_vk) if os.path.exists(mono_vk) else None,
        "proof_bytes": os.path.getsize(mono_proof) if os.path.exists(mono_proof) else None,
    }


def bls_nova(args, fname, fam, input_json, store, store_path):
    fdir = os.path.join(SCRIPT_DIR, fam["dir"])
    nova_r1cs = os.path.join(fdir, fam["nova_r1cs"])
    steps_dir = os.path.join(args.workdir, f"{fname}_steps")
    nova_pk = os.path.join(args.workdir, f"{fname}_nova.pk")
    nova_vk = os.path.join(args.workdir, f"{fname}_nova.vk")
    ivc = os.path.join(args.workdir, f"{fname}_ivc.json")
    compression_r1cs = os.path.join(args.workdir, f"{fname}_compression.r1cs")
    compression_proof = os.path.join(args.workdir, f"{fname}_compression.proof.json")
    slim_proof = os.path.join(args.workdir, f"{fname}_slim.proof.json")

    print("  BLS NOVA (in-tree)")
    step0 = os.path.join(steps_dir, "step_0000.wtns")
    if os.path.exists(step0) and not args.force:
        print("    step witnesses: reused")
    else:
        # The SMT step generator is wire-compatible with the cko step circuit
        # (both decompose Ed25519 scalar mul into 255 BitElementMulAny steps).
        gen_script = os.path.join(SCRIPT_DIR, "CardanoKeyOwnershipSMT", "gen_smt_nova_steps.py")
        dt, _ = run_timed(["python3", gen_script, "--input", input_json,
                           "--wasm", os.path.join(fdir, fam["nova_wasm"]),
                           "--dir", steps_dir, "--steps", str(args.steps)])
        store[f"{fname}_nova_steps"] = dt
        print(f"    step witnesses: {dt:.1f}s")

    # Impl 9: NIFS + Groth16 compression (default path)
    if os.path.exists(nova_pk) and os.path.exists(nova_vk) and not args.force:
        print("    ceremony (compression): reused")
    else:
        dt, _ = run_timed([args.nova, "fold", "--nifs", "--circuit", nova_r1cs,
                           "--steps", steps_dir, "--out", ivc,
                           "--compression-r1cs", compression_r1cs])
        store[f"{fname}_nova_fold_impl9"] = dt
        print(f"    fold + emit compression r1cs: {dt:.1f}s")
        dt, _ = run_timed([args.trusted_setup, "ceremony-dev", "--sparse", "--circuit", compression_r1cs,
                           "--proving-key", nova_pk, "--verifying-key", nova_vk])
        store[f"{fname}_nova_ceremony_impl9"] = dt
        print(f"    ceremony (compression): {dt:.1f}s")

    dt, _ = run_timed([args.nova, "compress", "--circuit", nova_r1cs, "--steps", steps_dir,
                       "--proving-key", nova_pk, "--out", compression_proof])
    store[f"{fname}_nova_compress_impl9"] = dt
    print(f"    compress (Groth16): {dt:.1f}s")

    dt, _ = run_timed([args.nova, "verify", "--ivc", ivc,
                       "--compression-proof", compression_proof, "--compression-vk", nova_vk])
    store[f"{fname}_nova_verify_impl9"] = dt
    print(f"    verify (Groth16 compression): {dt:.1f}s")

    # Impl 11: transparent slim proof
    dt, _ = run_timed([args.nova, "compress", "--slim", "--circuit", nova_r1cs,
                       "--steps", steps_dir, "--out", slim_proof])
    store[f"{fname}_nova_compress_impl11"] = dt
    print(f"    compress (slim): {dt:.1f}s")

    dt, _ = run_timed([args.nova, "verify", "--ivc", ivc, "--slim-proof", slim_proof])
    store[f"{fname}_nova_verify_impl11"] = dt
    print(f"    verify (slim): {dt:.1f}s")
    json.dump(store, open(store_path, "w"), indent=2)

    return {
        "impl9_pk_bytes": os.path.getsize(nova_pk) if os.path.exists(nova_pk) else None,
        "impl9_vk_bytes": os.path.getsize(nova_vk) if os.path.exists(nova_vk) else None,
        "impl9_proof_bytes": os.path.getsize(compression_proof) if os.path.exists(compression_proof) else None,
        "impl11_proof_bytes": os.path.getsize(slim_proof) if os.path.exists(slim_proof) else None,
    }


# ---------------------------------------------------------------------------
# NovaSlim phase
# ---------------------------------------------------------------------------

def parse_nova_slim_log(path):
    """Parse benchmark_nova output (same format as nova-slim/benchmarks/run_benchmarks.py)."""
    out = {}
    for line in open(path):
        if line.startswith("nifs fold"):
            # Matches both "nifs fold (baseline): ..." and "nifs fold (parallel): ..."
            parts = line.split()
            out["fold_s"] = float(parts[3])
            out["fold_ms_per_step"] = float(parts[6])
        elif line.startswith("sumcheck compress:"):
            out["compress_s"] = float(line.split()[2])
        elif line.startswith("verify (slim):"):
            out["verify_slim_s"] = float(line.split()[2])
        elif line.startswith("verify (full):"):
            out["verify_full_s"] = float(line.split()[2])
        elif line.startswith("slim proof:"):
            out["slim_proof_bytes"] = int(line.split()[2])
        elif line.startswith("sumcheck proof (full):"):
            out["full_proof_bytes"] = int(line.split()[3])
        elif line.startswith("nifs bundle:"):
            out["bundle_bytes"] = int(line.split()[2])
    return out


def nova_slim_benchmark(args, fname, fam, bench_bin, store, store_path):
    fdir = os.path.join(SCRIPT_DIR, fam["dir"])
    # Try the BLS step circuit first.  NovaSlim should accept any circom R1CS
    # that satisfies n_pub_in == n_pub_out.  The BLS `cardano_ed25519_ownership_nova`
    # and nova-slim `ed25519_verify_nova` are structurally the same BitElementMulAny
    # step, so the constraint count and witness layout match.
    nova_slim_r1cs = os.path.join(fdir, fam["nova_r1cs"])
    steps_dir = os.path.join(args.workdir, f"{fname}_steps")

    if not os.path.exists(nova_slim_r1cs):
        sys.exit(f"R1CS not found: {nova_slim_r1cs}")
    if not os.path.exists(steps_dir) or not os.path.exists(os.path.join(steps_dir, "step_0000.wtns")):
        sys.exit(f"step witnesses not found in {steps_dir}; run BLS Nova phase first")

    print("  NOVASLIM (upstream)")
    log_base = os.path.join(args.workdir, f"{fname}_nova_slim_base.log")
    log_par = os.path.join(args.workdir, f"{fname}_nova_slim_parallel.log")

    if os.path.exists(log_base) and not args.force:
        print("    benchmark (base): reused (see existing log)")
        store[f"{fname}_nova_slim_base"] = store.get(f"{fname}_nova_slim_base", 0.0)
        base = parse_nova_slim_log(log_base)
    else:
        dt = run_logged([bench_bin, "--curve", "bls12-381", "--commitment", args.commitment,
                         "--circuit", nova_slim_r1cs, "--steps", steps_dir, "--limit", str(args.steps)],
                        log_base)
        store[f"{fname}_nova_slim_base"] = dt
        print(f"    benchmark (base): {dt:.1f}s")
        base = parse_nova_slim_log(log_base)

    if args.no_parallel:
        parallel = {}
    elif os.path.exists(log_par) and not args.force:
        print("    benchmark (parallel): reused (see existing log)")
        store[f"{fname}_nova_slim_parallel"] = store.get(f"{fname}_nova_slim_parallel", 0.0)
        parallel = parse_nova_slim_log(log_par)
    else:
        dt = run_logged([bench_bin, "--curve", "bls12-381", "--commitment", args.commitment,
                         "--opt-parallel", "--circuit", nova_slim_r1cs, "--steps", steps_dir,
                         "--limit", str(args.steps)],
                        log_par)
        store[f"{fname}_nova_slim_parallel"] = dt
        print(f"    benchmark (parallel): {dt:.1f}s")
        json.dump(store, open(store_path, "w"), indent=2)
        parallel = parse_nova_slim_log(log_par)

    return {"base": base, "parallel": parallel}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(args, fname, fam, groth16_meta, nova_meta, nova_slim_meta, store):
    s = lambda k: store.get(f"{fname}_{k}")
    key = s("input") or 0.0

    mono_first = key + sum(s(k) or 0 for k in ("mono_witness", "mono_ceremony", "mono_prove", "mono_verify"))
    mono_steady = key + sum(s(k) or 0 for k in ("mono_witness", "mono_prove", "mono_verify"))

    nova9_first = key + sum(s(k) or 0 for k in ("nova_steps", "nova_fold_impl9", "nova_ceremony_impl9",
                                                  "nova_compress_impl9", "nova_verify_impl9"))
    nova9_steady = key + sum(s(k) or 0 for k in ("nova_steps", "nova_fold_impl9",
                                                  "nova_compress_impl9", "nova_verify_impl9"))

    ns_base = nova_slim_meta["base"]
    ns_par = nova_slim_meta["parallel"]

    print(f"\n## {fam['label']} — {fam['mono_constraints']:,} monolithic constraints / "
          f"{args.steps} x {fam['step_constraints']:,} step constraints")
    print()
    print("  | Phase | Groth16 mono | BLS Nova Impl 9 | BLS Nova Impl 11 | NovaSlim upstream |")
    print("  |---|---|---|---|---|")
    print(f"  | key + circuit input | {fmt_sec(key)} | {fmt_sec(key)} | {fmt_sec(key)} | {fmt_sec(key)} |")
    print(f"  | witness / step gen | {fmt_sec(s('mono_witness'))} | {fmt_sec(s('nova_steps'))} | {fmt_sec(s('nova_steps'))} | {fmt_sec(s('nova_steps'))} |")
    print(f"  | ceremony (one-time) | {fmt_sec(s('mono_ceremony'))} | {fmt_sec(s('nova_ceremony_impl9'))} | none | none |")
    print(f"  | fold | — | {fmt_sec(s('nova_fold_impl9'))} | {fmt_sec(s('nova_fold_impl9'))} | {fmt_sec(ns_base.get('fold_s'))} ({fmt_sec(ns_par.get('fold_s'))} par) |")
    print(f"  | compress / prove | {fmt_sec(s('mono_prove'))} | {fmt_sec(s('nova_compress_impl9'))} | {fmt_sec(s('nova_compress_impl11'))} | {fmt_sec(ns_base.get('compress_s'))} ({fmt_sec(ns_par.get('compress_s'))} par) |")
    print(f"  | verify | {fmt_sec(s('mono_verify'))} | {fmt_sec(s('nova_verify_impl9'))} | {fmt_sec(s('nova_verify_impl11'))} | {fmt_sec(ns_base.get('verify_slim_s'))} ({fmt_sec(ns_par.get('verify_slim_s'))} par) |")
    print(f"  | **e2e first run** | **{fmt_sec(mono_first)}** | **{fmt_sec(nova9_first)}** | **{fmt_sec(nova9_steady)}** | **{fmt_sec(key + s('nova_steps') + ns_base.get('fold_s', 0) + ns_base.get('compress_s', 0) + ns_base.get('verify_slim_s', 0))}** |")
    print(f"  | **e2e steady** | **{fmt_sec(mono_steady)}** | **{fmt_sec(nova9_steady)}** | **{fmt_sec(nova9_steady)}** | **{fmt_sec(key + s('nova_steps') + ns_base.get('fold_s', 0) + ns_base.get('compress_s', 0) + ns_base.get('verify_slim_s', 0))}** |")
    print(f"  | proof size | {fmt_bytes(groth16_meta.get('proof_bytes'))} | {fmt_bytes(nova_meta.get('impl9_proof_bytes'))} | {fmt_bytes(nova_meta.get('impl11_proof_bytes'))} | {fmt_bytes(ns_base.get('slim_proof_bytes'))} |")
    print(f"  | vk size | {fmt_bytes(groth16_meta.get('vk_bytes'))} | {fmt_bytes(nova_meta.get('impl9_vk_bytes'))} | none | none |")

    # Save machine-readable summary too.
    summary = {
        "family": fname,
        "label": fam["label"],
        "steps": args.steps,
        "groth16": {
            "constraints": fam["mono_constraints"],
            "first_s": mono_first,
            "steady_s": mono_steady,
            "proof_bytes": groth16_meta.get("proof_bytes"),
            "vk_bytes": groth16_meta.get("vk_bytes"),
        },
        "bls_nova_impl9": {
            "step_constraints": fam["step_constraints"],
            "first_s": nova9_first,
            "steady_s": nova9_steady,
            "proof_bytes": nova_meta.get("impl9_proof_bytes"),
            "vk_bytes": nova_meta.get("impl9_vk_bytes"),
        },
        "bls_nova_impl11": {
            "step_constraints": fam["step_constraints"],
            "proof_bytes": nova_meta.get("impl11_proof_bytes"),
        },
        "nova_slim": {
            "step_constraints": fam["step_constraints"],
            "base": ns_base,
            "parallel": ns_par,
        },
    }
    summary_path = os.path.join(args.workdir, f"{fname}_summary.json")
    json.dump(summary, open(summary_path, "w"), indent=2)
    print(f"\n  machine-readable summary: {summary_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Competitive benchmark: Groth16 / BLS Nova / NovaSlim")
    ap.add_argument("--family", choices=["cko", "smt", "all"], default="all")
    ap.add_argument("--steps", type=int, default=255)
    ap.add_argument("--workdir", default="/tmp/opencode/bench_nova_slim")
    ap.add_argument("--nova-slim-dir", default=DEFAULT_NOVA_SLIM)
    ap.add_argument("--groth16", default=DEFAULT_BLS_GROTH16)
    ap.add_argument("--nova", default=DEFAULT_BLS_NOVA)
    ap.add_argument("--trusted-setup", default=DEFAULT_BLS_TRUSTED_SETUP)
    ap.add_argument("--smt-cli", default=DEFAULT_SMT_CLI)
    ap.add_argument("--snarkjs", default="snarkjs")
    ap.add_argument("--cardano-address", default="cardano-address")
    ap.add_argument("--commitment", choices=["pedersen", "sis", "hash"], default="pedersen",
                    help="NovaSlim commitment scheme (default: pedersen)")
    ap.add_argument("--skip-build", action="store_true", help="assume binaries already built")
    ap.add_argument("--skip-bls", action="store_true", help="only run NovaSlim on existing BLS artifacts")
    ap.add_argument("--no-parallel", action="store_true", help="skip NovaSlim --opt-parallel pass")
    ap.add_argument("--force", action="store_true", help="re-run all phases even if artifacts exist")
    args = ap.parse_args()

    args.nova_slim_dir = os.path.abspath(args.nova_slim_dir)
    os.makedirs(args.workdir, exist_ok=True)

    fams = ["cko", "smt"] if args.family == "all" else [args.family]

    if not args.skip_build:
        build_bls_binaries(args)
    bench_bin = build_nova_slim_binary(args)

    for arg in ("groth16", "nova", "trusted_setup", "smt_cli"):
        path = getattr(args, arg)
        if not os.path.exists(path):
            sys.exit(f"required BLS binary not found: {path} (run without --skip-build)")

    store_path = os.path.join(args.workdir, "bench_times.json")
    store = json.load(open(store_path)) if os.path.exists(store_path) else {}

    for fname in fams:
        fam = FAMILIES[fname]
        print(f"\n{'='*70}")
        print(f"# {fam['label']} ({args.steps} steps)")
        print(f"{'='*70}")

        pay_xsk, pay_vk = ensure_keypair(args.workdir, args.cardano_address)
        input_json = bls_generate_input(args, fname, fam, pay_xsk, pay_vk, store)

        if not args.skip_bls:
            groth16_meta = bls_groth16_mono(args, fname, fam, input_json, store, store_path)
            nova_meta = bls_nova(args, fname, fam, input_json, store, store_path)
        else:
            # Load metadata from disk if skipping BLS phases.
            groth16_meta = {}
            nova_meta = {}

        nova_slim_meta = nova_slim_benchmark(args, fname, fam, bench_bin, store, store_path)

        json.dump(store, open(store_path, "w"), indent=2)
        print_summary(args, fname, fam, groth16_meta, nova_meta, nova_slim_meta, store)


if __name__ == "__main__":
    main()
