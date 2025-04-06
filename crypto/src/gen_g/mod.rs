mod errors;
pub use errors::GenGError;

use crate::Ring;
use crate::helper::gcd;
use crate::ring::errors::RingError;
use rand::prelude::{SeedableRng, SliceRandom, StdRng};

// Implement From<RingError> for GenGError
impl From<RingError> for GenGError {
    fn from(_err: RingError) -> Self {
        // Map RingError to a suitable GenGError variant
        GenGError::ConstructionFailed // Or define a more specific variant
    }
}

/// Implements the GEN-G(a, c, l, k) algorithm.
///
/// Generates a defining sequence `P` used for constructing ring operation tables.
///
/// # Parameters
/// * `a`: Coefficient 'a' for the linear function f(i) = a*i + c.
/// * `c`: Coefficient 'c' for the linear function f(i) = a*i + c.
/// * `l`: Parameter 'l' from the description, must be > 0 and divide `k`.
/// * `k`: The order (length of the sequence), where k = l*m. Must be > 0.
///
/// # Constraints
/// * `k > 0`
/// * `l > 0` and `k % l == 0`
/// * `gcd(a, k) == 1`
/// * `gcd(a, m) == 1`, where `m = k / l`.
///
/// # Returns
/// * `Ok(Vec<usize>)`: The generated sequence `P` of length `k`.
/// * `Err(GenGError)`: An error if constraints are not met or an internal
///   issue occurs.
///
/// # Algorithm Steps & Notes
/// 1. Generates an initial sequence `b` where `b[i] = (a*i + c) % k`.
/// 2. **Transforms `b` using a seeded shuffle.** The sequence `b` generated in
///    Step 1 is shuffled using a pseudo-random number generator initialized
///    with the provided `seed`. This ensures the transformation is repeatable
///    if the same seed is used.
/// 3. Modifies the shuffled `b` to place `0` at the last position (`b[k-1]`)
///    and `1` at the first position (`b[0]`) by swapping elements.
/// 4. Constructs the final sequence `P` based on the modified `b`.
///
/// # Time Complexity
/// The description states O(k log^2 k) due to multiplications. The shuffle in
/// Step 2 is typically O(k). Other implemented steps are O(k).
pub fn gen_g(a: i64, c: i64, l: i64, k: i64, seed: i64) -> Result<Vec<i64>, GenGError> {
    // Basic validation
    if k <= 0 {
        return Err(GenGError::KMustBePositive); // Correct variant
    }
    if l <= 0 || k % l != 0 {
        return Err(GenGError::InvalidLValue);
    }
    // Check gcd(a, k) == 1 requirement
    let g = gcd(a.abs(), k.abs());
    if g != 1 {
        return Err(GenGError::GcdAKConstraintNotMet(g)); // Correct variant with value
    }

    let k_usize = k as usize;
    let mut b: Vec<i64> = vec![0; k_usize + 1];

    // Operator 1) of GEN-G
    let k_u64 = k as u64;
    let ring = Ring::try_with(k_u64)?;

    // Calculate b[i+1] = a*i + c (mod k) for i=0..k-1
    for i_usize in 0..k_usize {
        let i = i_usize as i64;
        let term1 = ring.mul(a, i);
        b[i_usize + 1] = ring.add(term1, c);
    }

    // Operator 2) Transform b (example: shuffle)
    let mut rng = StdRng::seed_from_u64(seed as u64);
    b[1..].shuffle(&mut rng);

    // Operator 3) Ensure b[k] = 0 and b[1] = 1
    let pos_0 = b[1..].iter().position(|&x| x == 0);
    if let Some(p0) = pos_0 {
        let actual_idx0 = p0 + 1;
        if actual_idx0 != k_usize {
            b.swap(actual_idx0, k_usize);
        }
    } else {
        return Err(GenGError::ValueZeroNotFound); // Correct variant
    }

    let pos_1_after_swap = b[1..].iter().position(|&x| x == 1);
    if let Some(p1) = pos_1_after_swap {
        let actual_idx1 = p1 + 1;
        if actual_idx1 != 1 {
            b.swap(actual_idx1, 1);
        }
    } else {
        return Err(GenGError::ValueOneNotFound); // Correct variant
    }

    // Operator 4) Return the defining row b[1..k]
    Ok(b[1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: i64 = 42;

    #[test]
    fn test_example_1_with_seed() {
        let k = 6;
        let a = 1;
        let c = 4;
        let l = 2;

        let p_expected = vec![1, 4, 2, 3, 5, 0];

        let result = match gen_g(a, c, l, k, TEST_SEED) {
            Ok(result) => result,
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        };

        assert_eq!(result, p_expected);
    }

    #[test]
    fn test_generates_same_p_with_same_seed() {
        let p1 = gen_g(3, 1, 2, 4, TEST_SEED).unwrap();
        let p2 = gen_g(3, 1, 2, 4, TEST_SEED).unwrap();

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_generates_different_p_with_different_seed() {
        let p1 = gen_g(3, 1, 2, 4, TEST_SEED).unwrap();
        let p2 = gen_g(3, 1, 2, 4, TEST_SEED + 1).unwrap();

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_gcd_ak_constraint_error() {
        let result = gen_g(2, 4, 2, 6, TEST_SEED);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), GenGError::GcdAKConstraintNotMet(2));
    }

    #[test]
    fn test_invalid_l_value() {
        let result = gen_g(1, 1, 0, 6, TEST_SEED);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), GenGError::InvalidLValue);

        let result = gen_g(1, 1, 4, 6, TEST_SEED);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), GenGError::InvalidLValue);
    }

    #[test]
    fn test_k0_error() {
        let result = gen_g(1, 1, 1, 0, TEST_SEED);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), GenGError::KMustBePositive);
    }
}
