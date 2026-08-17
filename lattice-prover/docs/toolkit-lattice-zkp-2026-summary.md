# Toolkit for Succinct Lattice-Based Zero Knowledge Proofs

**Source:** IBM Research Europe (Biasioli, Bolboceanu, Lyubashevsky, Merino-Gallardo, Osadnik, Seiler, Steuer)
**Date:** 2026
**File:** `ToolkitLatticeZKP2026IMB.pdf` (in `~/Downloads/`)

## Key Contribution

First concrete construction and implementation that adds **zero-knowledge** to LaBRADOR, achieving **proof sizes under 100KB** for arbitrarily large statements — the smallest among all post-quantum schemes.

## Architecture

The proof system combines two components:

1. **LaBRADOS** (improved LaBRADOR) — succinct, non-ZK base protocol
2. **LNP-Lite** — compressed linear-size zero-knowledge proof

### Protocol Flow

```
Input relation (large witness)
    │
    ▼
┌─────────────────────────────────────────┐
│  LaBRADOS iterations (sublinear)        │
│  - Reduces witness size                 │
│  - Inner messages are simulatable       │
│  - NOT fully ZK yet                     │
└─────────────────────────────────────────┘
    │
    ▼ (small witness)
┌─────────────────────────────────────────┐
│  LNP-Lite (linear-size, ZK)            │
│  - Masks secret in z                    │
│  - Only last prover message is large    │
│  - Provides zero-knowledge              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  LaBRADOS rounds (succinct)             │
│  - Proves knowledge of masked opening   │
│  - No ZK requirements anymore           │
│  - Result: succinct proof               │
└─────────────────────────────────────────┘
    │
    ▼
Succinct ZK proof (~100-110KB)
```

## Performance

| Metric | Value |
|--------|-------|
| **Proof size (non-ZK)** | ~100KB |
| **Proof size (ZK-enabled)** | ~110KB |
| **ZK overhead** | ~10KB (constant) |
| **Ring** | R = Z[X]/(X^d + 1), d = 512 |
| **Assumptions** | M-SIS, M-LWE, M-LWR |
| **Implementation** | LaZer library (C++) |

### Benchmark Results (single core, Intel Tiger Lake-H)

| Use Case | Prover Time | Verifier Time |
|----------|-------------|---------------|
| PRG expansion | Fast | Milliseconds |
| Collision-resistant hash | Fast | Milliseconds |
| Merkle tree membership | Fast | Milliseconds |
| Blind signature | Fast | Milliseconds |

**Key insight:** Proof size remains **constant** across use cases and input sizes — dominated by the last LaBRADOR round.

## Comparison with Lova

| Aspect | Toolkit (IBM) | Lova (Fenzi et al.) |
|--------|---------------|---------------------|
| **Proof size** | ~100-110KB | **Dozens of MB** |
| **Assumption** | Module-SIS (structured) | Unstructured SIS |
| **Modulus** | Standard lattice params | q = 2^64 (power-of-two) |
| **Rounds** | Few (succinct) | t > 300 |
| **Prover time** | Fast | > 10 minutes |
| **ZK** | ✅ Built-in | ❌ Not yet |
| **Maturity** | Implemented (LaZer) | Research only |

## Relevance to lattice-prover (Lova implementation)

### Why This Matters

The IBM toolkit demonstrates that **lattice-based ZKPs can be practical** with proof sizes under 100KB. This is in stark contrast to Lova's current megabyte-scale proofs.

### Potential Improvements for Lova

1. **Compress final instance** — The paper's approach (LaBRADOS + LNP-Lite) could inspire a similar compression strategy for Lova's final verification
2. **Tighter soundness** — The high soundness error requiring t > 300 rounds is the main bottleneck; techniques from this paper might help
3. **Structured commitments** — Module-SIS (used by IBM) is more efficient than unstructured SIS (used by Lova), though less conservative

### Trade-offs

| | Lova (Unstructured) | IBM Toolkit (Module) |
|---|---|---|
| **Security assumption** | Simpler, more conservative | Structured, newer |
| **Proof size** | Large | Small |
| **Concrete efficiency** | Poor | Good |
| **Post-quantum** | ✅ | ✅ |

### Recommendation

The IBM toolkit provides a **practical blueprint** for achieving sub-100KB lattice-based ZKPs. While Lova's unstructured SIS assumption is more conservative, the proof size gap (MB vs KB) suggests that:

1. **For production:** Consider Module-SIS-based schemes (LatticeFold, ProtogaLattice) for practical deployment
2. **For research:** Lova remains valuable as a theoretical foundation with simpler assumptions
3. **Hybrid approach:** Use Lova's conceptual framework but with more efficient commitment schemes

## References

- LaBRADOR: Beullens, Seiler, Crypto 2023
- LaZer: Lyubashevsky, Seiler, Steuer, CCS 2024
- LNP: Lyubashevsky, Nguyen, Plançon, Crypto 2022
- LatticeFold: Boneh, Chen, ePrint 2024/257
- ProtogaLattice: Balbás, Nitulescu, Plançon, ePrint 2026/1317
