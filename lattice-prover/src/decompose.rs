use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::Ring;
use lattirust_arithmetic::ring::Z2_64;
use lattirust_arithmetic::ring::representatives::WithSignedRepresentative;

/// Decompose a vector into base-`b` balanced digits.
///
/// Given `v ∈ Z_q^n`, returns a vector of `k` digit-vectors `D[0..k]`
/// such that `v = Σ_{i=0}^{k-1} b^i * D[i]` (mod q), with each digit
/// in `[-(b-1)/2, (b-1)/2]`.
pub fn decompose_vector(
    v: &Vector<Z2_64>,
    base: i64,
    num_digits: usize,
) -> Vec<Vector<Z2_64>> {
    let n = v.len();
    let mut digits: Vec<Vector<Z2_64>> = (0..num_digits)
        .map(|_| Vector::from_element(n, Z2_64::ZERO))
        .collect();

    for j in 0..n {
        let mut remaining = v[j].as_signed_representative();
        let half_base = base / 2;

        for i in 0..num_digits {
            let digit = ((remaining % base) + base) % base;
            let balanced = if digit > half_base || (digit == half_base && remaining < 0) {
                digit - base
            } else {
                digit
            };
            digits[i][j] = Z2_64::from(balanced);
            remaining = (remaining - balanced) / base;
        }
    }

    digits
}

/// Recompose a vector from base-`b` digits.
///
/// Returns `v = Σ_{i=0}^{k-1} b^i * D[i]` (mod q).
pub fn recompose_vector(
    digits: &[Vector<Z2_64>],
    base: i64,
) -> Vector<Z2_64> {
    let n = digits[0].len();
    let b = Z2_64::from(base);
    let mut result = Vector::from_element(n, Z2_64::ZERO);
    let mut power = Z2_64::ONE;

    for d in digits {
        for j in 0..n {
            result[j] = result[j] + power * d[j];
        }
        power = power * b;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_decompose_recompose_base2() {
        let v = Vector::from_vec(vec![
            Z2_64::from(5i64),
            Z2_64::from(7i64),
            Z2_64::from(0i64),
            Z2_64::from(1i64),
        ]);
        let digits = decompose_vector(&v, 2, 8);
        let reconstructed = recompose_vector(&digits, 2);

        for j in 0..v.len() {
            assert_eq!(v[j], reconstructed[j], "mismatch at index {}", j);
        }
    }

    #[test]
    fn test_decompose_recompose_base4() {
        let v = Vector::from_vec(vec![
            Z2_64::from(42i64),
            Z2_64::from(100i64),
            Z2_64::from(255i64),
        ]);
        let digits = decompose_vector(&v, 4, 5);
        let reconstructed = recompose_vector(&digits, 4);

        for j in 0..v.len() {
            assert_eq!(v[j], reconstructed[j], "mismatch at index {}", j);
        }
    }

    #[test]
    fn test_digit_bounds_base2() {
        let v = Vector::from_vec(vec![Z2_64::from(12345i64), Z2_64::from(-6789i64)]);
        let digits = decompose_vector(&v, 2, 32);

        for (i, d) in digits.iter().enumerate() {
            for j in 0..d.len() {
                let val = d[j].as_signed_representative();
                assert!(
                    val >= -1 && val <= 1,
                    "digit D[{}][{}] = {} out of bounds [-1, 1]",
                    i, j, val,
                );
            }
        }
    }

    #[test]
    fn test_zero_vector() {
        let v = Vector::from_element(4, Z2_64::ZERO);
        let digits = decompose_vector(&v, 2, 8);
        let reconstructed = recompose_vector(&digits, 2);

        for j in 0..v.len() {
            assert_eq!(v[j], reconstructed[j]);
        }
    }

    proptest::proptest! {
        #[test]
        fn test_decompose_recompose_roundtrip(
            vals in proptest::collection::vec(any::<i16>().prop_map(|x| Z2_64::from(x as i64)), 8),
            base in 2i64..8,
        ) {
            let v = Vector::from_vec(vals);
            let num_digits = 32;
            let digits = decompose_vector(&v, base, num_digits);
            let reconstructed = recompose_vector(&digits, base);

            for j in 0..v.len() {
                prop_assert_eq!(v[j], reconstructed[j], "roundtrip failed at index {}", j);
            }
        }
    }
}
