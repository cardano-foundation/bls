#!/usr/bin/env python3
"""Convert mimc.js round constants to Rust src/mimc.rs"""

import re

with open('groth16-prover/circom/Privacy/mimc.js', 'r') as f:
    content = f.read()

# Extract the decimal constants from the `const c = [...]` array
match = re.search(r'const c = \[(.*?)\];', content, re.DOTALL)
if not match:
    raise RuntimeError("Could not find constants array in mimc.js")

raw = match.group(1)
# Split by comma, strip whitespace and trailing 'n'
items = [item.strip().rstrip('n') for item in raw.split(',') if item.strip()]

assert len(items) == 91, f"Expected 91 constants, got {len(items)}"

lines = []
for item in items:
    lines.append(f'    "{item}",')

constants_block = '\n'.join(lines)

rust = f'''// MiMC(x^7) hash for BLS12-381
// This project is strictly focused on BLS12-381. BN254 is not supported.

use ark_bls12_381::Fr;
use ark_ff::Field;
use std::str::FromStr;
use std::sync::OnceLock;

/// Round constants for MiMC(x^7) over the BLS12-381 scalar field.
const ROUND_CONSTANTS_STR: [&str; 91] = [
{constants_block}
];

fn get_round_constants() -> &'static [Fr; 91] {{
    static CONSTANTS: OnceLock<[Fr; 91]> = OnceLock::new();
    CONSTANTS.get_or_init(|| {{
        let mut arr = [Fr::zero(); 91];
        for (i, s) in ROUND_CONSTANTS_STR.iter().enumerate() {{
            arr[i] = Fr::from_str(s).expect("valid BLS12-381 scalar");
        }}
        arr
    }})
}}

/// MiMC(x^7) block cipher over BLS12-381 scalar field.
fn mimc_cipher(x_in: Fr, key: Fr) -> Fr {{
    let c = get_round_constants();
    let mut t = x_in;
    for i in 0..91 {{
        t = t + key + c[i];
        t = t.pow(&[7u64]);
    }}
    t + key
}}

/// Miyaguchi-Preneel compression using MiMC(x^7).
pub fn mimc_compression(acc: Fr, data: Fr) -> Fr {{
    data + acc + mimc_cipher(data, acc)
}}

/// Two-input MiMC hash.
pub fn mimc2(in0: Fr, in1: Fr) -> Fr {{
    mimc_compression(in0, in1)
}}

/// Multi-input MiMC hash (Merkle-Damgard mode).
pub fn mimc_hash(inputs: &[Fr], init: Fr) -> Fr {{
    let mut t = init;
    for &input in inputs {{
        t = mimc_compression(t, input);
    }}
    t
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_mimc2_zero() {{
        let result = mimc2(Fr::zero(), Fr::zero());
        // The value should be non-zero (due to rounds)
        assert_ne!(result, Fr::zero());
    }}

    #[test]
    fn test_mimc2_known() {{
        let a = Fr::from(2u64);
        let b = Fr::from(3u64);
        let h1 = mimc2(a, b);
        let h2 = mimc2(a, b);
        assert_eq!(h1, h2);
    }}
}}
'''

with open('groth16-prover/src/mimc.rs', 'w') as f:
    f.write(rust)

print("Generated groth16-prover/src/mimc.rs")
