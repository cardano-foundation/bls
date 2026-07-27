# Step 1.1: R1CS matrices and witness

**What this step does.** Before any cryptography happens, we must express the circuit as a system of rank-1 constraints. Each constraint says: "the dot product of the left matrix row with the witness, multiplied by the dot product of the right matrix row with the witness, equals the dot product of the output matrix row with the witness."

## Paper and pencil

There are 4 multiplication gates, so we need 4 constraints. The witness vector has 14 entries:

```
w = [  1, 100,  1,  2,  3,  4,  5,  6,  7,  8,  2, 12, 30, 56 ]
     const out  a   b   c   d   e   f   g   h  t1  t2  t3  t4
     [  0,   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13 ]   ← indices
```

**Constraint 0:** `t1 = a * b`
- Left side picks `a` (wire 2)  → `L[0][2] = 1`
- Right side picks `b` (wire 3) → `R[0][3] = 1`
- Output picks `t1` (wire 10)   → `O[0][10] = 1`

**Constraint 1:** `t2 = c * d`
- Left side picks `c` (wire 4)  → `L[1][4] = 1`
- Right side picks `d` (wire 5) → `R[1][5] = 1`
- Output picks `t2` (wire 11)   → `O[1][11] = 1`

**Constraint 2:** `t3 = e * f`
- Left side picks `e` (wire 6)  → `L[2][6] = 1`
- Right side picks `f` (wire 7) → `R[2][7] = 1`
- Output picks `t3` (wire 12)   → `O[2][12] = 1`

**Constraint 3:** `t4 = g * h`
- Left side picks `g` (wire 8)  → `L[3][8] = 1`
- Right side picks `h` (wire 9) → `R[3][9] = 1`
- Output picks `t4` (wire 13)   → `O[3][13] = 1`

All other entries are zero.

### Matrix form

In matrix form (all unlisted entries are 0), with the witness vector alongside for reference:

```
w =    [  1  100   1   2   3   4   5   6   7   8   2  12  30  56 ]
        const out   a   b   c   d   e   f   g   h  t1  t2  t3  t4
        ----- ---   -   -   -   -   -   -   -   -  --  --  --  --
L[0]  = [  0    0   1   0   0   0   0   0   0   0   0   0   0   0 ]    picks a
L[1]  = [  0    0   0   0   1   0   0   0   0   0   0   0   0   0 ]    picks c
L[2]  = [  0    0   0   0   0   0   1   0   0   0   0   0   0   0 ]    picks e
L[3]  = [  0    0   0   0   0   0   0   0   1   0   0   0   0   0 ]    picks g

R[0]  = [  0    0   0   1   0   0   0   0   0   0   0   0   0   0 ]    picks b
R[1]  = [  0    0   0   0   0   1   0   0   0   0   0   0   0   0 ]    picks d
R[2]  = [  0    0   0   0   0   0   0   1   0   0   0   0   0   0 ]    picks f
R[3]  = [  0    0   0   0   0   0   0   0   0   1   0   0   0   0 ]    picks h

O[0]  = [  0    0   0   0   0   0   0   0   0   0   1   0   0   0 ]    picks t1
O[1]  = [  0    0   0   0   0   0   0   0   0   0   0   1   0   0 ]    picks t2
O[2]  = [  0    0   0   0   0   0   0   0   0   0   0   0   1   0 ]    picks t3
O[3]  = [  0    0   0   0   0   0   0   0   0   0   0   0   0   1 ]    picks t4
```

### Verifying constraint 0 in detail

Each R1CS constraint checks `(L[i]·w) * (R[i]·w) = O[i]·w`:

```
L[0]·w = 0·1 + 0·100 + 1·1 + 0·2 + ... = 1     (picks a)
R[0]·w = 0·1 + 0·100 + 0·1 + 1·2 + ... = 2     (picks b)
O[0]·w = 0·1 + 0·100 + ... + 1·2 + ... = 2     (picks t1)

(L[0]·w) * (R[0]·w) = 1 * 2 = 2  =  O[0]·w  ✓
```

### All four constraints

```
constraint 0:  1 * 2  = 2   ✓   (t1 = a·b)
constraint 1:  3 * 4  = 12  ✓   (t2 = c·d)
constraint 2:  5 * 6  = 30  ✓   (t3 = e·f)
constraint 3:  7 * 8  = 56  ✓   (t4 = g·h)
```

**Public inputs:** wire 0 (constant `1`) and wire 1 (output `out = 100`).
**Private inputs:** wires 2–9 (`a` through `h`).
**Intermediate wires:** wires 10–13 (`t1` through `t4`).
