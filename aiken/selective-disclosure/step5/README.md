# Step 5 — Compliant shielded transfer with full auditor reveal (amount + address)

Reproducible, copy-paste e2e for an **auditable privacy transaction that also
reveals identity to the auditor**: a shielded privacy-pool spend (reusing Step 3
verbatim via `privacy_pool_lib.circom`) whose private input amount **and** the
recipient's address id are encrypted to a designated auditor's public key with a
multi-message Twisted ElGamal ciphertext. Only the auditor — holding the viewing
key `sk_audit` such that `pk_audit = sk_audit * G` — can decrypt the amount
**and** the address; everyone else sees only ciphertexts.

```
E     = r * G                           shared ephemeral (public)
C     = in_amount  * H + r * pk_audit   amount ciphertext (public)
C_a0  = addr_limb0 * H + r * pk_audit   address low  u16 limb (public)
C_a1  = addr_limb1 * H + r * pk_audit   address high u16 limb (public)

m * H = C_x - sk_audit * E              auditor reveal (off-chain decrypt)
addr  = limb0 + 2^16 * limb1
```

The address is bound to the spend via a public commitment
`addr_commitment = Poseidon(recipient_addr, nullifier)`.

Two proof paths:

- `groth16_e2e.sh` — one monolithic `privacy_pool_viewable_addr.circom` proof
  (Step 3 pool + amount ElGamal + 2× address-limb ElGamal,
  `--sparse` ceremony/prove).
- `novaslim_e2e.sh` — `elgamal_viewkey_addr_nova.circom` folds the multi-message
  auditor encryption as a single Nova step; the public IVC state (`wit[1]`) is a
  Poseidon commitment to the shared `E` and the three `C` points, so the slim
  proof binds the revealed ciphertexts.

Both scripts print the on-chain auditor decrypt checks: they recover the hidden
amount (e.g. `100`) and the recipient address (e.g. `0x1234`, limbs `4660`/`0`).

## Run

```bash
./groth16_e2e.sh
./novaslim_e2e.sh
```

Overrides: `DEPTH=` (Groth16 pool). Artifacts in
`/tmp/sd_step5_{groth16,novaslim}/` (`OUT=` to override).

## Prerequisites

Same as Step 4: `circom`, `snarkjs`, Python 3, `--prime bls12381`, and the
NovaSlim CLI at [`nova-slim`](../../../nova-slim).

## On-chain

| Path | On-chain verifier | Datum / redeemer |
|------|-------------------|------------------|
| Groth16 | `aiken/groth16` gate (pairing check) | datum = `vk`, redeemer = `proof` + public `(merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee, pk_audit, addr_commitment, E, C, C_a0, C_a1)` |
| NovaSlim | [`nova-slim/cardano/nova-slim-verifier`](../../../nova-slim/cardano/nova-slim-verifier) | datum = `NifsBundle`, redeemer = `SlimProof` |

A policy layer (not enforced in-circuit) pins `pk_audit` to the pool's
registered auditor; the on-chain gate can whitelist that public key.

Groth16 also emits `pp_vk.ak`; NovaSlim emits `vk_slim.proof.cbor`.

## Representative timing (dev machine)

| Phase | Groth16 | NovaSlim (1 step) |
|-------|---------|-------------------|
| witness prep | 0.3 s | 0.3 s |
| compile | 8.6 s | 1.9 s |
| witness | 1.8 s | 1.0 s |
| trusted setup | 29.7 s | — (transparent) |
| prove / fold+compress | 13.4 s | 28.2 + 52.8 s |
| verify | 0.17 s | 0.01 s |
| **proof size** | **192 B** | **758 B** |
