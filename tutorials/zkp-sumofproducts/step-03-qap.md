# Steps 1.3–1.5: QAP polynomials and target polynomial

**What these steps do.** The R1CS matrices are a *discrete* description of the circuit: they tell us what happens at each constraint index `j = 0, 1, 2, 3`. Cryptography needs a *continuous* description: polynomials that encode the same information, so that checking the circuit reduces to checking a single identity between polynomials. The transformation from matrices to polynomials is the **Quadratic Arithmetic Program (QAP)**.

For each wire `i` we build three polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` such that at constraint point `j`:

```
u_i(j) = L[j][i]
v_i(j) = R[j][i]
w_i(j) = O[j][i]
```

## Lagrange basis polynomials

The simplest way to do this is **Lagrange interpolation**: we pick four distinct points (our constraint indices `0, 1, 2, 3`), build the four *Lagrange basis polynomials* that are `1` at one point and `0` at the others, and use them as a basis.

The Lagrange basis for points `{0, 1, 2, 3}`:

```
L_0(x) = (x−1)(x−2)(x−3) / (0−1)(0−2)(0−3) = −(x³ − 6x² + 11x − 6) / 6
       = −⅙x³ + x² − ¹¹⁄₆x + 1

L_1(x) = x(x−2)(x−3) / (1)(−1)(−2) = (x³ − 5x² + 6x) / 2
       = ½x³ − ⁵⁄₂x² + 3x

L_2(x) = x(x−1)(x−3) / (2)(1)(−1) = −(x³ − 4x² + 3x) / 2
       = −½x³ + 2x² − ³⁄₂x

L_3(x) = x(x−1)(x−2) / (3)(2)(1) = (x³ − 3x² + 2x) / 6
       = ⅙x³ − ½x² + ⅓x
```

(All arithmetic is in Fr, so "½" means the modular inverse of `2`, "⅓" means the modular inverse of `3`, etc.)

Verify by evaluating at each constraint point — each basis polynomial returns `1` at its own point and `0` at the others:

| x | `L_0(x)` | `L_1(x)` | `L_2(x)` | `L_3(x)` |
|---|----------|----------|----------|----------|
| 0 | 1        | 0        | 0        | 0        |
| 1 | 0        | 1        | 0        | 0        |
| 2 | 0        | 0        | 1        | 0        |
| 3 | 0        | 0        | 0        | 1        |

## Per-variable QAP polynomials

Because our R1CS matrices contain only `0` and `1`, each QAP polynomial is simply one of these basis polynomials (or zero). A variable that appears on the left of constraint `j` gets `u_i(x) = L_j(x)`, and so on:

| Variable | Wire | `u_i(x)` (left) | `v_i(x)` (right) | `w_i(x)` (output) |
|----------|------|-------------------|--------------------|---------------------|
| 0 | `1` (const) | 0 | 0 | 0 |
| 1 | `out` | 0 | 0 | `L_3(x)` |
| 2 | `a` | `L_0(x)` | 0 | 0 |
| 3 | `b` | 0 | `L_0(x)` | 0 |
| 4 | `c` | `L_1(x)` | 0 | 0 |
| 5 | `d` | 0 | `L_1(x)` | 0 |
| 6 | `e` | `L_2(x)` | 0 | 0 |
| 7 | `f` | 0 | `L_2(x)` | 0 |
| 8 | `g` | `L_3(x)` | 0 | 0 |
| 9 | `h` | 0 | `L_3(x)` | 0 |
| 10 | `t1` | 0 | 0 | `L_0(x)` |
| 11 | `t2` | 0 | 0 | `L_1(x)` |
| 12 | `t3` | 0 | 0 | `L_2(x)` |
| 13 | `t4` | 0 | 0 | `L_3(x)` |

## Concrete example for constraint 1

For constraint 1 (`t2 = c * d`, at point `x = 1`):

```
u_4(x) = L_1(x) = ½x³ − ⁵⁄₂x² + 3x
v_5(x) = L_1(x) = ½x³ − ⁵⁄₂x² + 3x
w_11(x) = L_1(x) = ½x³ − ⁵⁄₂x² + 3x

u_4(1) = ½ − ⁵⁄₂ + 3 = 1
v_5(1) = 1
w_11(1) = 1

l(1) = ... + a_4 · u_4(1) + ... = ... + 3 · 1 + ... = 3    (picks c = 3)
r(1) = ... + a_5 · v_5(1) + ... = ... + 4 · 1 + ... = 4    (picks d = 4)
o(1) = ... + a_11 · w_11(1) + ... = ... + 12 · 1 + ... = 12  (picks t2 = 12)

l(1) · r(1) = 3 · 4 = 12 = o(1)  ✓
```

## The target polynomial

If the witness is correct, then at every constraint point `j`:

```
l(j) · r(j) = o(j)
```

This means the polynomial `l(x)·r(x) − o(x)` is zero at `x = 0, 1, 2, 3`. Therefore it is divisible by the *target polynomial* `T(x)`, which is the product of `(x − j)` over all constraint points:

```
T(x) = (x−0)(x−1)(x−2)(x−3) = x(x−1)(x−2)(x−3)
     = x⁴ − 6x³ + 11x² − 6x
```

`T(x)` is a degree-4 polynomial that vanishes at all constraint points.

## QAP verification at constraint points

At each constraint point `j`, the QAP polynomials must reproduce the R1CS columns. Since the QAP polynomials are built from Lagrange basis polynomials that are `1` at their own point and `0` at others, this is guaranteed by construction. The QAP is a degree-3 polynomial system (max degree of any `u_i`, `v_i`, `w_i` is 3), and `T(x)` is degree 4.

The witness polynomials `l(x)`, `r(x)`, `o(x)` will be computed in [Step 1.10](step-08-witness-polys.md), and the quotient `h(x)` in [Step 1.11](step-09-quotient.md).
