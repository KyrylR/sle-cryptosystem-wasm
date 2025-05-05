//! Implementation of ring ops using modular arithmetic.

use crate::errors::SLECryptoError;

use super::extended_gcd;

use serde::{Deserialize, Serialize};

/// Represents a finite ring Z_k using modular arithmetic.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ring {
    pub modulus: u64,
}

impl Ring {
    /// Create a new Ring with the given modulus.
    ///
    /// The modulus must be greater than 1.
    pub fn try_with(modulus: u64) -> Result<Self, SLECryptoError> {
        if modulus <= 1 {
            return Err(SLECryptoError::InvalidModulus(format!(
                "Modulus must be greater than 1, got {}",
                modulus
            )));
        }

        Ok(Ring { modulus })
    }

    /// Returns the modulus of the ring.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(13).unwrap();
    /// assert_eq!(ring.modulus(), 13);
    /// ```
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    /// Normalizes a value to be within the range `[0, modulus - 1]`.
    ///
    /// Handles negative values correctly by adding the modulus.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(10).unwrap();
    /// assert_eq!(ring.normalize(15), 5);
    /// assert_eq!(ring.normalize(-3), 7);
    /// assert_eq!(ring.normalize(0), 0);
    /// assert_eq!(ring.normalize(10), 0);
    /// ```
    pub fn normalize(&self, value: i64) -> i64 {
        let m = self.modulus as i64;

        let rem = value % m;
        if rem < 0 {
            return rem + m;
        }

        rem
    }

    /// Computes `(a + b) mod modulus`.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(10).unwrap();
    /// assert_eq!(ring.add(7, 5), 2);
    /// assert_eq!(ring.add(-2, 5), 3);
    /// assert_eq!(ring.add(12, 13), 5);
    /// ```
    pub fn add(&self, a: i64, b: i64) -> i64 {
        let a_norm = self.normalize(a);
        let b_norm = self.normalize(b);

        self.normalize(a_norm.wrapping_add(b_norm))
    }

    /// Computes `(a - b) mod modulus`.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(10).unwrap();
    /// assert_eq!(ring.sub(7, 5), 2);
    /// assert_eq!(ring.sub(3, 5), 8);
    /// assert_eq!(ring.sub(-2, 3), 5);
    /// ```
    pub fn sub(&self, a: i64, b: i64) -> i64 {
        let a_norm = self.normalize(a);
        let b_norm = self.normalize(b);

        self.normalize(a_norm.wrapping_sub(b_norm))
    }

    /// Computes `(a * b) mod modulus`.
    ///
    /// Uses `i128` internally to prevent overflow during multiplication before the modulo operation.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(10).unwrap();
    /// assert_eq!(ring.mul(7, 5), 5); // 35 mod 10 = 5
    /// assert_eq!(ring.mul(-2, 6), 8); // -12 mod 10 = 8
    /// assert_eq!(ring.mul(4, 5), 0); // 20 mod 10 = 0
    /// ```
    pub fn mul(&self, a: i64, b: i64) -> i64 {
        let a_norm = self.normalize(a);
        let b_norm = self.normalize(b);

        let result = (a_norm as i128 * b_norm as i128) % (self.modulus as i128);

        self.normalize(result as i64)
    }

    /// Computes the additive inverse `-a mod modulus`.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(10).unwrap();
    /// assert_eq!(ring.neg(3), 7);
    /// assert_eq!(ring.neg(0), 0);
    /// assert_eq!(ring.neg(7), 3);
    /// assert!(ring.add(3, ring.neg(3)) == 0);
    /// ```
    pub fn neg(&self, a: i64) -> i64 {
        if a == 0 {
            return 0;
        }

        self.normalize(((-a as i128) % self.modulus as i128) as _)
    }

    /// Computes the modular multiplicative inverse `a^-1 mod modulus`.
    ///
    /// The inverse exists if and only if `gcd(a, modulus) == 1`.
    /// Uses the Extended Euclidean Algorithm.
    ///
    /// # Errors
    ///
    /// Returns `SLECryptoError::NoInverse` if the inverse does not exist (i.e., `gcd(a, modulus) != 1`).
    /// Returns `SLECryptoError::NoInverse` if `a` is 0.
    ///
    /// # Example
    ///
    /// ```
    /// # use sle_crypto::ring::Ring;
    /// let ring = Ring::try_with(10).unwrap();
    /// assert_eq!(ring.inv(3).unwrap(), 7); // 3 * 7 = 21 = 1 mod 10
    /// assert_eq!(ring.inv(7).unwrap(), 3);
    /// assert_eq!(ring.inv(9).unwrap(), 9); // 9 * 9 = 81 = 1 mod 10
    /// assert!(ring.inv(2).is_err()); // gcd(2, 10) = 2
    /// assert!(ring.inv(0).is_err());
    /// ```
    pub fn inv(&self, a: i64) -> Result<i64, SLECryptoError> {
        let a_norm = self.normalize(a);
        if a_norm == 0 {
            return Err(SLECryptoError::NoInverse(format!(
                "Cannot invert 0 in mod {}",
                self.modulus
            )));
        }

        let (g, x, _) = extended_gcd(a_norm, self.modulus as i64);
        if g != 1 {
            return Err(SLECryptoError::NoInverse(format!(
                "Modular inverse does not exist for {} mod {} (gcd={})",
                a_norm, self.modulus, g
            )));
        }

        Ok(self.normalize(x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_creation() {
        assert!(Ring::try_with(11).is_ok());
        assert!(Ring::try_with(25).is_ok());
        assert!(Ring::try_with(1).is_err());
    }

    #[test]
    fn test_element_normalization() -> Result<(), SLECryptoError> {
        let ring = Ring::try_with(11)?;
        assert_eq!(ring.normalize(5), 5);
        assert_eq!(ring.normalize(16), 5);
        assert_eq!(ring.normalize(-6), 5);
        Ok(())
    }

    #[test]
    fn test_addition() -> Result<(), SLECryptoError> {
        let ring = Ring::try_with(11)?;
        assert_eq!(ring.add(5, 8), 2);
        assert_eq!(ring.add(-3, 8), 5);
        Ok(())
    }

    #[test]
    fn test_subtraction() -> Result<(), SLECryptoError> {
        let ring = Ring::try_with(11)?;
        assert_eq!(ring.sub(5, 8), 8);
        assert_eq!(ring.sub(8, 5), 3);
        Ok(())
    }

    #[test]
    fn test_multiplication() -> Result<(), SLECryptoError> {
        let ring = Ring::try_with(11)?;
        assert_eq!(ring.mul(5, 8), 7);
        assert_eq!(ring.mul(-2, 8), 6);
        Ok(())
    }

    #[test]
    fn test_negation() -> Result<(), SLECryptoError> {
        let ring = Ring::try_with(11)?;
        assert_eq!(ring.neg(5), 6);
        assert_eq!(ring.neg(0), 0);
        Ok(())
    }

    #[test]
    fn test_inversion() -> Result<(), SLECryptoError> {
        let ring = Ring::try_with(11)?;
        assert_eq!(ring.inv(5)?, 9);
        Ok(())
    }
}
