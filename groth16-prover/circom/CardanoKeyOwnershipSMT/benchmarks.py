#!/usr/bin/env python3
"""Benchmarks for CardanoKeyOwnershipSMT circuit."""

import json
import time
import sys
import os
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_e2e import generate_test_input

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WASM = os.path.join(SCRIPT_DIR, "cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm")
R1CS = os.path.join(SCRIPT_DIR, "cardano_key_ownership_smt.r1cs")


def benchmark_witness_generation(depth=4, iterations=5):
    times = []
    for i in range(iterations):
        generate_test_input(depth=depth, output_file=f"/tmp/bench_input_{i}.json")
        start = time.time()
        result = subprocess.run(
            ["snarkjs", "wc", WASM, f"/tmp/bench_input_{i}.json", f"/tmp/bench_witness_{i}.wtns"],
            capture_output=True, text=True,
        )
        elapsed = time.time() - start
        if result.returncode == 0:
            times.append(elapsed)
        else:
            print(f"  Iteration {i} failed: {result.stderr.strip()}")
    if times:
        avg = sum(times) / len(times)
        print(f"  Witness generation: avg={avg:.3f}s min={min(times):.3f}s max={max(times):.3f}s ({len(times)}/{iterations} succeeded)")
    else:
        print("  Witness generation: all iterations failed")


def benchmark_proof_generation(depth=4, iterations=5):
    zkey = os.path.join(SCRIPT_DIR, "cardano_key_ownership_smt_final.zkey")
    if not os.path.exists(zkey):
        print("  Skipped: proving key not found")
        return
    times = []
    for i in range(iterations):
        generate_test_input(depth=depth, output_file=f"/tmp/bench_input_{i}.json")
        start = time.time()
        result = subprocess.run(
            ["snarkjs", "groth16", "prove", zkey, f"/tmp/bench_input_{i}.json",
             f"/tmp/bench_proof_{i}.json", f"/tmp/bench_public_{i}.json"],
            capture_output=True, text=True,
        )
        elapsed = time.time() - start
        if result.returncode == 0:
            times.append(elapsed)
        else:
            print(f"  Iteration {i} failed: {result.stderr.strip()}")
    if times:
        avg = sum(times) / len(times)
        print(f"  Proof generation: avg={avg:.3f}s min={min(times):.3f}s max={max(times):.3f}s ({len(times)}/{iterations} succeeded)")
    else:
        print("  Proof generation: all iterations failed")


def benchmark_verification(depth=4, iterations=10):
    vk = os.path.join(SCRIPT_DIR, "cardano_key_ownership_smt_verification_key.json")
    if not os.path.exists(vk):
        print("  Skipped: verification key not found")
        return
    times = []
    for i in range(iterations):
        generate_test_input(depth=depth, output_file=f"/tmp/bench_input_{i}.json")
        start = time.time()
        result = subprocess.run(
            ["snarkjs", "groth16", "verify", vk, f"/tmp/bench_public_{i}.json", f"/tmp/bench_proof_{i}.json"],
            capture_output=True, text=True,
        )
        elapsed = time.time() - start
        if result.returncode == 0:
            times.append(elapsed)
        else:
            print(f"  Iteration {i} failed: {result.stderr.strip()}")
    if times:
        avg = sum(times) / len(times)
        print(f"  Proof verification: avg={avg:.3f}s min={min(times):.3f}s max={max(times):.3f}s ({len(times)}/{iterations} succeeded)")
    else:
        print("  Proof verification: all iterations failed")


def main():
    print("CardanoKeyOwnershipSMT Benchmarks")
    print("==================================")
    print()

    print("Witness Generation (depth=4):")
    benchmark_witness_generation(depth=4, iterations=5)
    print()

    print("Proof Generation (depth=4):")
    benchmark_proof_generation(depth=4, iterations=5)
    print()

    print("Proof Verification (depth=4):")
    benchmark_verification(depth=4, iterations=10)
    print()


if __name__ == "__main__":
    main()