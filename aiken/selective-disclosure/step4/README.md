# Step 4 — Compliant shielded transfer (viewing-key auditor reveal)

Reproducible, copy-paste e2e for an **auditable privacy transaction**: a
shielded privacy-pool spend (reusing Step 3 verbatim via
`privacy_pool_lib.circom`) whose private input amount is additionally encrypted
to a designated auditor's public key with Twisted ElGamal. Only the auditor —
holding the viewing key `sk_audit` such that `pk_audit = sk_audit * G` — can
decrypt the amount; everyone else sees only ciphertexts.

```
E = r * G                       ephemeral component (public)
C = in_amount * H + r * pk_audit   commitment   (public)
in_amount * H = C - sk_audit * E   auditor reveal (off-chain decrypt)
```

Two proof paths:

- `groth16_e2e.sh` — one monolithic `privacy_pool_viewable.circom` proof
  (Step 3 pool + ElGamal-to-auditor, `--sparse` ceremony/prove).
- `novaslim_e2e.sh` — `elgamal_viewkey_nova.circom` folds the auditor encryption
  as a single Nova step; the public IVC state (`wit[1]`) is a Poseidon
  commitment to the ciphertext, so the slim proof binds the revealed `(E, C)`.

Both scripts print the on-chain auditor decrypt check that `in_amount * H =
C - sk_audit * E`, recovering the hidden amount (e.g. `100`).

## Run

```bash
./groth16_e2e.sh
./novaslim_e2e.sh
```

Overrides: `DEPTH=` (Groth16 pool). Artifacts in
`/tmp/sd_step4_{groth16,novaslim}/` (`OUT=` to override).

## Prerequisites

Same as Step 3: `circom`, `snarkjs`, Python 3, `--prime bls12381`, and the
NovaSlim CLI at [`nova-slim`](../../../nova-slim).

## On-chain

| Path | On-chain verifier | Datum / redeemer |
|------|-------------------|------------------|
| Groth16 | `aiken/groth16` gate (pairing check) | datum = `vk`, redeemer = `proof` + public `(merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee, pk_audit, E, C)` |
| NovaSlim | [`nova-slim/cardano/nova-slim-verifier`](../../../nova-slim/cardano/nova-slim-verifier) | datum = `NifsBundle`, redeemer = `SlimProof` |

A policy layer (not enforced in-circuit) pins `pk_audit` to the pool's
registered auditor; the on-chain gate can whitelist that public key.

Groth16 also emits `pp_vk.ak`; NovaSlim emits `vk_slim.proof.cbor`.

## Representative timing (dev machine)

| Phase | Groth16 | NovaSlim (1 step) |
|-------|---------|-------------------|
| witness prep | 0.3 s | 0.3 s |
| compile | 3 s | 1.5 s |
| witness | 0.9 s | 0.9 s |
| trusted setup | 14 s | — (transparent) |
| prove / fold+compress | 7.6 s | 11.4 + 24.4 s |
| verify | 0.05 s | 0.01 s |
| **proof size** | **192 B** | **684 B** |
