# Groth16 walkthrough: SumOfProducts circuit

This directory contains a step-by-step walkthrough of the Groth16 pipeline for the **4-gate SumOfProducts** circuit:

```
t1 = a * b
t2 = c * d
t3 = e * f
t4 = g * h
out = t1 + t2 + t3 + t4
```

With witness inputs `a=1, b=2, c=3, d=4, e=5, f=6, g=7, h=8`:

```
out = 1·2 + 3·4 + 5·6 + 7·8 = 2 + 12 + 30 + 56 = 100
```

The witness vector is `[1, 100, 1, 2, 3, 4, 5, 6, 7, 8, 2, 12, 30, 56]` (14 entries: constant, output, 8 inputs, 4 intermediates).

## Steps

| Step | File | What it covers |
|------|------|----------------|
| 1.1 | [step-01-r1cs.md](step-01-r1cs.md) | R1CS matrices and witness |
| 1.2 | (see [main tutorial](../zkp-from-first-principles.md#step-12-the-finite-field)) | The finite field Fr |
| 1.3–1.5 | [step-03-qap.md](step-03-qap.md) | QAP polynomials and target polynomial |
| 1.6 | (see [main tutorial](../zkp-from-first-principles.md#step-16-toxic-waste)) | Toxic waste |
| 1.7 | [step-05-srs.md](step-05-srs.md) | Structured Reference String |
| 1.8 | (see [main tutorial](../zkp-from-first-principles.md#step-18-crs-fixed-points)) | CRS fixed points |
| 1.9 | [step-07-psi.md](step-07-psi.md) | Per-variable CRS |
| 1.10 | [step-08-witness-polys.md](step-08-witness-polys.md) | Witness polynomials l(x), r(x), o(x) |
| 1.11 | [step-09-quotient.md](step-09-quotient.md) | Quotient polynomial h(x) |
| 1.12 | [step-10-proof-a.md](step-10-proof-a.md) | Proof element A |
| 1.13 | [step-11-proof-b.md](step-11-proof-b.md) | Proof element B |
| 1.14 | [step-12-proof-c.md](step-12-proof-c.md) | Proof element C |
| 1.15 | [step-13-public-input.md](step-13-public-input.md) | Public-input commitment V |
| 1.16 | [step-14-pairing.md](step-14-pairing.md) | Pairing check |

## Parameters

| Parameter | Value | Role |
|-----------|-------|------|
| `τ` (tau)   | 3   | Secret evaluation point |
| `α` (alpha) | 5   | Mixed term for proof element C |
| `β` (beta)  | 7   | Mixed term for proof elements B and C |
| `γ` (gamma) | 11  | Denominator for public-input CRS elements |
| `δ` (delta) | 13  | Denominator for private-input CRS elements |

All arithmetic is in the BLS12-381 scalar field Fr with modulus:

```
q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
```
