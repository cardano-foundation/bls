# Step 1.9: Per-variable CRS

**What this step does.** The prover needs a way to turn the witness values into curve points for proof element `C`. For each wire `i`, the trusted setup computes a scalar that encodes the wire's QAP polynomials evaluated at `τ`, mixed with `α` and `β`, and scaled by either `1/γ` (for public wires) or `1/δ` (for private wires). These scalars are multiplied by `G1` to produce the **per-variable CRS** points.

## Paper and pencil

For each wire `i`, compute:

```
combined_i = v_i(τ)·α + u_i(τ)·β + w_i(τ)
```

Then:
- If `i` is a **public** wire: `psi_scalar_i = combined_i / γ`
- If `i` is a **private** wire: `psi_scalar_i = combined_i / δ`

The point is `psi_scalar_i · G1`.

**Public wires:** wire 0 (constant `1`) and wire 1 (output `out`).
**Private wires:** everything else (wires 2–13).

## Lagrange basis at τ = 4

With τ = 4 and constraint points `{0, 1, 2, 3}`:

```
L_0(4) = (4−1)(4−2)(4−3) / (0−1)(0−2)(0−3) = 3·2·1 / (−1)(−2)(−3) = 6 / (−6) = −1
L_1(4) = 4·(4−2)(4−3) / (1)(−1)(−2) = 4·2·1 / 2 = 4
L_2(4) = 4·(4−1)(4−3) / (2)(1)(−1) = 4·3·1 / (−2) = −6
L_3(4) = 4·(4−1)(4−2) / (3)(2)(1) = 4·3·2 / 6 = 4
```

So: `L_0(4) = −1`, `L_1(4) = 4`, `L_2(4) = −6`, `L_3(4) = 4`.

## Combined scalars for each variable

Using the QAP polynomial assignments from [Step 1.3](step-03-qap.md):

| Variable | Wire | `u_i(τ)` | `v_i(τ)` | `w_i(τ)` | `combined = v·α + u·β + w` | Public/Private | `÷ γ` or `÷ δ` |
|----------|------|-----------|-----------|-----------|----------------------------|----------------|-------------------|
| 0 | `1` (const) | 0 | 0 | 0 | 0 | Public | `0/γ = 0` |
| 1 | `out` | 0 | 0 | `L_3(4)=4` | 4 | Public | `4/11` |
| 2 | `a` | `L_0(4)=−1` | 0 | 0 | `(−1)·7 = −7` | Private | `−7/13` |
| 3 | `b` | 0 | `L_0(4)=−1` | 0 | `(−1)·5 = −5` | Private | `−5/13` |
| 4 | `c` | `L_1(4)=4` | 0 | 0 | `4·7 = 28` | Private | `28/13` |
| 5 | `d` | 0 | `L_1(4)=4` | 0 | `4·5 = 20` | Private | `20/13` |
| 6 | `e` | `L_2(4)=−6` | 0 | 0 | `(−6)·7 = −42` | Private | `−42/13` |
| 7 | `f` | 0 | `L_2(4)=−6` | 0 | `(−6)·5 = −30` | Private | `−30/13` |
| 8 | `g` | `L_3(4)=4` | 0 | 0 | `4·7 = 28` | Private | `28/13` |
| 9 | `h` | 0 | `L_3(4)=4` | 0 | `4·5 = 20` | Private | `20/13` |
| 10 | `t1` | 0 | 0 | `L_0(4)=−1` | −1 | Private | `−1/13` |
| 11 | `t2` | 0 | 0 | `L_1(4)=4` | 4 | Private | `4/13` |
| 12 | `t3` | 0 | 0 | `L_2(4)=−6` | −6 | Private | `−6/13` |
| 13 | `t4` | 0 | 0 | `L_3(4)=4` | 4 | Private | `4/13` |

## Why this matters

Proof element `C` is computed as `Σ a_i · Psi_P_G1[i] + h(τ)·T(τ)/δ·G1`. The per-variable CRS points are what let the prover "commit" to the witness values inside the proof, without ever revealing them. The verifier, meanwhile, recomputes the public-input commitment `V = Σ a_i · Psi_V_G1[i]` from the public wires only. Because public and private wires are divided by different denominators (`γ` vs. `δ`), the verifier can isolate the public part without learning the private part.
