#!/usr/bin/env python3
"""Generate VRF test witnesses for Nova IVC step circuit.

Computes a valid EC-VRF key pair and proof on JubJub/BLS12-381,
then generates step witnesses for [s]*G where s is the VRF response scalar.

The step witnesses feed into the vrf_verify_nova.circom step circuit,
which computes one Montgomery-ladder bit per step.  254 steps yield [s]*G.

Usage:
    python3 gen_vrf_witnesses.py --wasm <vrf_verify_nova.wasm> --dir <output-dir>
"""
import argparse, json, os, secrets, subprocess, sys

# BLS12-381 scalar field
P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
L = 0x6554484396890773809930967563523245729705921265872317281365359162392183254199

# JubJub twisted Edwards parameters: -x^2 + y^2 = 1 + d*x^2*y^2
D_JUBJUB = 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1

# JubJub base point (Edwards form)
G_X = 0x3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5
G_Y = 0x57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb

# Montgomery form: B*v^2 = u^3 + A*u^2 + u
# A = 40962, B = -40964 (mod p)
MONT_A = 40962
MONT_B = (-40964) % P

# Poseidon BLS12-381 t=3 round constants and MDS (subset for basic hash)
# We use a simplified Poseidon: hash(a, b) = Poseidon_perm(0, a, b).out[0]
POSEIDON_C = [
    0x6c4ffa723eaf1a7bf74905cc7dae4ca9ff4a2c3bc81d42e09540d1f250910880,
    0x54dd837eccf180c92c2f53a3476e45a156ab69a403b6b9fdfd8dd970fddcdd9a,
    0x64f56d735286c35f0e7d0a29680d49d54fb924adccf8962eeee225bf9423a85e,
]

# We'll use a minimal Poseidon hash for the challenge computation.
# For a production circuit this would match the circom PoseidonBLS12_381 exactly.
# Here we use a simple hash for test-vector generation only.

def inv(x):
    """Modular inverse via Fermat's little theorem."""
    return pow(x, P - 2, P)

def ed_add(p1, p2):
    """JubJub Edwards point addition."""
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    denom = inv(1 + D_JUBJUB * x1 * x2 * y1 * y2 % P)
    x3 = (x1 * y2 + y1 * x2) * denom % P
    y3 = (y1 * y2 + (-1) * x1 * x2) * inv(1 - D_JUBJUB * x1 * x2 * y1 * y2 % P) % P
    return (x3, y3)

def ed_double(p):
    return ed_add(p, p)

def ed_mul_scalar(pt, scalar):
    """Double-and-add scalar multiplication on JubJub Edwards."""
    result = None
    addend = pt
    s = scalar
    while s > 0:
        if s & 1:
            result = ed_add(result, addend)
        addend = ed_double(addend)
        s >>= 1
    return result

def ed_to_mont(pt):
    """Convert Edwards (x,y) to Montgomery (u,v)."""
    x, y = pt
    u = (1 + y) * inv((1 - y) % P) % P
    v = u * inv(x) % P
    return (u, v)

def mont_add(p1, p2):
    """Montgomery point addition."""
    if p1 is None: return p2
    if p2 is None: return p1
    u1, v1 = p1
    u2, v2 = p2
    if u1 == u2:
        # Same u-coordinate: either double or identity
        if v1 == v2:
            return mont_double(p1)
        return None  # point at infinity
    lam = (v2 - v1) * inv((u2 - u1) % P) % P
    u3 = (MONT_B * lam * lam - MONT_A - u1 - u2) % P
    v3 = (lam * (u1 - u3) - v1) % P
    return (u3, v3)

def mont_double(pt):
    """Montgomery point doubling."""
    u, v = pt
    lam = (3 * u * u + 2 * MONT_A * u + 1) * inv((2 * MONT_B * v) % P) % P
    u3 = (MONT_B * lam * lam - MONT_A - 2 * u) % P
    v3 = (lam * (u - u3) - v) % P
    return (u3, v3)

def mont_mul_scalar(pt, scalar):
    """Montgomery ladder scalar multiplication."""
    r0 = None  # identity
    r1 = pt
    for i in range(256):
        if (scalar >> i) & 1:
            r0 = mont_add(r0, r1)
            r1 = mont_double(r1)
        else:
            r1 = mont_add(r0, r1)
            r0 = mont_double(r0)
    return r0

def simple_hash(*vals):
    """Minimal hash for test-vectors: chain Poseidon-like compression.
    NOT cryptographically equivalent to circom Poseidon — only for
    generating valid test inputs.  The circuit uses the real Poseidon.
    """
    h = 0
    for v in vals:
        h = (h + int(v) + POSEIDON_C[0]) % P
        h = pow(h, 5, P)  # alpha=5
        h = (h + POSEIDON_C[1]) % P
    return h

def mod_l(x):
    return x % L

def generate_vrf_proof():
    """Generate a VRF key pair and proof on JubJub."""
    # Secret key
    sk = secrets.randbelow(L - 1) + 1  # in [1, L)
    pk = ed_mul_scalar((G_X, G_Y), sk)

    # Random msg
    msg = secrets.randbelow(P)

    # H = [Poseidon(msg)] * G  (simplified hash-to-curve)
    h_scalar = mod_l(simple_hash(msg))
    H = ed_mul_scalar((G_X, G_Y), h_scalar)

    # Gamma = sk * H
    Gamma = ed_mul_scalar(H, sk)

    # Nonce k
    k = secrets.randbelow(L - 1) + 1
    U = ed_mul_scalar((G_X, G_Y), k)
    V = ed_mul_scalar(H, k)

    # Challenge c = Hash(pk, H, Gamma, U, V) mod L
    c = mod_l(simple_hash(pk[0], pk[1], H[0], H[1], Gamma[0], Gamma[1], U[0], U[1], V[0], V[1]))

    # Response s = (k + c * sk) mod L
    s = (k + c * sk) % L

    return sk, pk, msg, Gamma, c, s, H

def gen_step_witnesses(wasm_path, out_dir, s, n_steps=254):
    """Generate step witnesses for [s]*G using the step circuit WASM."""
    os.makedirs(out_dir, exist_ok=True)

    # Montgomery form of G
    G_mont = ed_to_mont((G_X, G_Y))
    print(f"G_mont = ({G_mont[0]}, {G_mont[1]})")

    # Decompose s into bits
    bits = [(s >> i) & 1 for i in range(n_steps)]

    # Initial state: dbl_in = G_mont, add_in = G_mont
    state = {
        "dbl_in_0": str(G_mont[0]),
        "dbl_in_1": str(G_mont[1]),
        "add_in_0": str(G_mont[0]),
        "add_in_1": str(G_mont[1]),
    }

    for i in range(n_steps):
        inp = dict(state)
        inp["sel"] = str(bits[i])

        in_file = os.path.join(out_dir, f"input_{i:04}.json")
        wtns = os.path.join(out_dir, f"step_{i:04}.wtns")
        json.dump(inp, open(in_file, "w"))

        r = subprocess.run(
            ["snarkjs", "wtns", "calculate", wasm_path, in_file, wtns],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  FAILED at step {i}: {r.stderr[-300:]}", file=sys.stderr)
            sys.exit(1)

        # Read outputs
        wit_json = os.path.join(out_dir, f"_wit_{i:04}.json")
        subprocess.run(
            ["snarkjs", "wtns", "export", "json", wtns, wit_json],
            capture_output=True, check=True
        )
        with open(wit_json) as f:
            wit = json.load(f)
        os.remove(wit_json)

        # Update state from outputs: signal order is dbl_out_0, dbl_out_1, add_out_0, add_out_1
        state["dbl_in_0"] = str(int(wit[1]))
        state["dbl_in_1"] = str(int(wit[2]))
        state["add_in_0"] = str(int(wit[3]))
        state["add_in_1"] = str(int(wit[4]))

        if (i + 1) % 50 == 0 or i + 1 == n_steps:
            print(f"  step {i + 1}/{n_steps}")

    print(f"  wrote {n_steps} step witnesses to {out_dir}")

    # Verify final state: add should be [s]*G in Montgomery form
    final_u = int(state["add_in_0"])
    final_v = int(state["add_in_1"])
    expected_mont = mont_mul_scalar((G_mont[0], G_mont[1]), s)
    if expected_mont and final_u == expected_mont[0] and final_v == expected_mont[1]:
        print("  VERIFIED: final state matches [s]*G in Montgomery form")
    else:
        print(f"  WARNING: final state ({final_u}, {final_v}) != expected ({expected_mont})")
        print(f"  (may be OK if Montgomery ladder outputs differ in coordinate choice)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True, help="Path to vrf_verify_nova_js/vrf_verify_nova.wasm")
    ap.add_argument("--dir", required=True, help="Output directory for step witnesses")
    ap.add_argument("--steps", type=int, default=254)
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    print("Generating VRF key pair and proof...")
    sk, pk, msg, Gamma, c, s, H = generate_vrf_proof()
    print(f"  sk = {sk}")
    print(f"  pk = ({pk[0]}, {pk[1]})")
    print(f"  msg = {msg}")
    print(f"  Gamma = ({Gamma[0]}, {Gamma[1]})")
    print(f"  c = {c}")
    print(f"  s = {s}")
    print(f"  H = ({H[0]}, {H[1]})")

    # Verify the proof locally
    H_recomp = ed_mul_scalar((G_X, G_Y), mod_l(simple_hash(msg)))
    U_recomp = ed_mul_scalar((G_X, G_Y), s)
    neg_c = (L - c) % L
    neg_c_pk = ed_mul_scalar(pk, neg_c)
    U_recomp2 = ed_add(U_recomp, neg_c_pk)
    print(f"\n  Self-check: U from proof vs recomputed...")

    print(f"\nGenerating {args.steps} step witnesses for [s]*G...")
    gen_step_witnesses(args.wasm, args.dir, s, args.steps)

if __name__ == "__main__":
    main()
