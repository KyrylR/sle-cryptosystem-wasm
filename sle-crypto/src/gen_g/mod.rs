use crate::errors::SLECryptoError;
use crate::ring::{Ring, Vector, gcd};

use rand::prelude::{SeedableRng, SliceRandom, StdRng};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Isomorphism {
    pub ring: Ring,
    pub substitution: Vector,
    pub definite_string: Vector,
    pub reverse_definite: Vector,
}

impl Isomorphism {
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
    /// * `l > 0`
    /// * `gcd(a, k) == 1`
    /// * `gcd(a, m) == 1`, where `m = k / l`.
    ///
    /// # Returns
    /// * `Ok((Vec<usize>, Vec<usize>))`: The generated sequence `b` and `p`.
    /// * `Err(SLECryptoError)`: An error if constraints are not met or an internal
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
    /// 4. Constructs the definitive vector `P` from the transformed `b` sequence.
    ///    The mapping is defined as `P[b[i]] = b[i+1]` for `i` in `[0, k-1)`.
    ///
    /// # Time Complexity
    /// The description states O(k log^2 k) due to multiplications. The shuffle in
    /// Step 2 is typically O(k). Other implemented steps are O(k).
    pub fn gen_g(a: i64, c: i64, l: i64, k: i64, seed: i64) -> Result<Self, SLECryptoError> {
        // Basic validation
        if k <= 0 {
            return Err(SLECryptoError::KMustBePositive);
        }
        if l <= 0 {
            return Err(SLECryptoError::InvalidLValue);
        }
        // Check gcd(a, k) == 1 requirement
        let g = gcd(a.abs(), k.abs());
        if g != 1 {
            return Err(SLECryptoError::GcdAKConstraintNotMet(g));
        }

        let k_usize = k as usize;
        let mut b: Vector = vec![0; k_usize];

        // Operator 1) of GEN-G
        let k_u64 = k as u64;
        let ring = Ring::try_with(k_u64)?;

        // Calculate b[i+1] = a*i + c (mod k) for i=0..k-1
        for i_usize in 0..k_usize {
            b[i_usize] = ring.add(ring.mul(a, i_usize as _), c);
        }

        // Operator 2) Transform b via shuffling
        b.shuffle(&mut StdRng::seed_from_u64(seed as u64));

        Isomorphism::construct_b_and_p(b, k_usize, ring)
    }

    /// Maps a value from Z_m to the isomorphic group G_m using the definite string.
    ///
    /// This function takes a value in the ring Z_m and maps it to its corresponding
    /// element in the isomorphic group G_m using the precomputed definite string.
    ///
    /// # Arguments
    /// * `value`: The value in Z_m to be mapped to G_m.
    ///
    /// # Returns
    /// The corresponding value in G_m.
    pub fn map_into(&self, value: i64) -> i64 {
        let normalized_value = self.ring.normalize(value);
        self.definite_string[normalized_value as usize]
    }

    /// Maps a value from G_m back to Z_m using the reverse definite string.
    ///
    /// This function takes a value in the isomorphic group G_m and maps it back
    /// to its corresponding element in the ring Z_m using the precomputed reverse
    /// definite string.
    ///
    /// # Arguments
    /// * `value`: The value in G_m to be mapped back to Z_m.
    ///
    /// # Returns
    /// The corresponding value in Z_m.
    pub fn map_back(&self, value: i64) -> i64 {
        let normalized_value = self.ring.normalize(value);
        self.reverse_definite[normalized_value as usize]
    }

    fn construct_b_and_p(
        mut b: Vector,
        k_usize: usize,
        ring: Ring,
    ) -> Result<Self, SLECryptoError> {
        // Operator 3) Ensure b[k] = 0 and b[1] = 1
        let Some(p0_pos) = b.iter().position(|&x| x == 0) else {
            return Err(SLECryptoError::ValueZeroNotFound);
        };
        b.swap(p0_pos, k_usize - 1);

        let Some(p1_pos) = b.iter().position(|&x| x == 1) else {
            return Err(SLECryptoError::ValueOneNotFound);
        };
        b.swap(p1_pos, 0);

        // Operator 4) <see doc>
        let mut p: Vector = vec![0; k_usize];
        p[0] = b[0];
        for i in 0..k_usize - 1 {
            p[b[i] as usize] = b[i + 1]
        }

        // Calculate the reverse mapping of definite_string
        // This creates a vector where reverse_b[b[i]] = i
        let mut reverse_b: Vector = vec![0; k_usize];
        for (i, &value) in b.iter().enumerate() {
            reverse_b[value as usize] = i as i64;
        }

        // Verify the reverse mapping is correct
        for i in 0..k_usize {
            if b[reverse_b[i] as usize] != i as i64 {
                return Err(SLECryptoError::InternalError(
                    "Failed to create reverse mapping for definite_string".to_string(),
                ));
            }
        }

        Ok(Self {
            ring,
            definite_string: b,
            substitution: p,
            reverse_definite: reverse_b,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: i64 = 42;

    #[test]
    fn test_construct_b_and_p() {
        let original_vec = vec![2, 5, 4, 1, 0, 3];
        let expected_b = vec![1, 5, 4, 2, 3, 0];
        let expected_p = vec![1, 5, 3, 0, 2, 4];

        let Ok(isomorphism) = Isomorphism::construct_b_and_p(
            original_vec.clone(),
            original_vec.len(),
            Ring::try_with(2).unwrap(),
        ) else {
            assert!(false, "Expected construct_b_and_p to succeed");
            return;
        };

        assert_eq!(isomorphism.definite_string, expected_b);
        assert_eq!(isomorphism.substitution, expected_p);
    }

    #[test]
    fn test_example_1_with_seed() {
        let k = 6;
        let a = 1;
        let c = 4;
        let l = 2;

        let b_expected = vec![1, 4, 2, 3, 5, 0];

        let result = match Isomorphism::gen_g(a, c, l, k, TEST_SEED) {
            Ok(result) => result,
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        };

        assert_eq!(result.definite_string, b_expected);
    }

    #[test]
    fn test_generates_same_p_with_same_seed() {
        let p1 = Isomorphism::gen_g(3, 1, 2, 4, TEST_SEED).unwrap();
        let p2 = Isomorphism::gen_g(3, 1, 2, 4, TEST_SEED).unwrap();

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_generates_different_p_with_different_seed() {
        let p1 = Isomorphism::gen_g(3, 1, 2, 4, TEST_SEED).unwrap();
        let p2 = Isomorphism::gen_g(3, 1, 2, 4, TEST_SEED + 1).unwrap();

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_gcd_ak_constraint_error() {
        let result = Isomorphism::gen_g(2, 4, 2, 6, TEST_SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_l_value() {
        let result = Isomorphism::gen_g(1, 1, 0, 6, TEST_SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_k0_error() {
        let result = Isomorphism::gen_g(1, 1, 1, 0, TEST_SEED);
        assert!(result.is_err());
    }
}
