use crate::ring::Ring;
use crate::system::errors::CryptoError;
use crate::system::matrix_ops::{Matrix, Vector, matrix_inverse, matrix_rank};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json; // Import serde_json

/// Parameters shared for cryptographic operations over the ring Z_m.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedParams {
    /// Modulus m for the ring Z_m.
    pub m: u64,
    /// Ring instance for operations in Z_m.
    pub ring: Ring,
    /// Number of equations p in the linear systems, also the message block size.
    pub p: usize,
    /// Number of variables q in the linear systems (typically q > p).
    pub q: usize,
}

impl SharedParams {
    /// Reconstructs the Ring object after deserialization.
    fn reconstruct_ring(&mut self) -> Result<(), CryptoError> {
        self.ring = Ring::try_with(self.m)?;
        Ok(())
    }
}

/// Secret parameters required for decryption.
/// These parameters allow reversing the transformation from l(x) to L(x).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecryptionSecrets {
    /// The inverse B^-1 of the transformation matrix B used in L(x). (Size: p x p).
    pub b_inv: Matrix,
    /// The inner constant vector a_inner used in the transformation. (Size: p x 1).
    pub a_inner: Vector,
    /// The outer constant vector a_outer used in the transformation. (Size: p x 1).
    pub a_outer: Vector,
}

/// Publicly known parameters required for encryption.
/// These parameters define the linear transformations l(x) = Ax and L(x) = Bx + a.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptionParams {
    /// The matrix A for the initial linear system l(x) = Ax. (Size: p x q).
    pub a: Matrix,
    /// The matrix B for the transformed linear system L(x) = Bx + a. (Size: p x p).
    pub b: Matrix,
    /// The inner constant vector a_inner used in the transformation. (Size: p x 1).
    pub a_inner: Vector,
    /// The outer constant vector a_outer used in the transformation. (Size: p x 1).
    pub a_outer: Vector,
}

/// Public key containing shared parameters and encryption-specific parameters.
/// This key is used to perform the encryption process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Shared ring and system parameters.
    pub shared: SharedParams,
    /// Parameters defining the encryption transformations (A, B, a_inner, a_outer).
    pub encryption_params: EncryptionParams,
}

impl PublicKey {
    /// Exports the public key to a JSON string.
    pub fn to_json(&self) -> Result<String, CryptoError> {
        serde_json::to_string(self).map_err(|e| {
            CryptoError::SerializationError(format!("PublicKey JSON export failed: {}", e))
        })
    }

    /// Imports a public key from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, CryptoError> {
        let mut key: PublicKey = serde_json::from_str(json_str).map_err(|e| {
            CryptoError::SerializationError(format!("PublicKey JSON import failed: {}", e))
        })?;
        key.shared.reconstruct_ring()?;
        Ok(key)
    }
}

/// Private key containing the corresponding public key and decryption secrets.
/// This key is used to perform the decryption process by reversing the transformation L(x).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    /// The public key associated with this private key.
    pub public_key: PublicKey,
    /// Secret parameters needed to reverse the encryption transformation (B^-1, a_inner, a_outer).
    pub decryption_secrets: DecryptionSecrets,
}

impl PrivateKey {
    /// Generates a new key pair for the cryptosystem.
    ///
    /// # Arguments
    /// * `m`: Modulus for the ring Z_m.
    /// * `p`: Number of equations (message block size).
    /// * `q`: Number of variables (must be >= p).
    /// * `seed`: A seed for deterministic random generation.
    ///
    /// # Returns
    /// A `PrivateKey` or a `CryptoError`.
    pub fn generate(m: u64, p: usize, q: usize, seed: u64) -> Result<PrivateKey, CryptoError> {
        if m <= 1 {
            return Err(CryptoError::InvalidParameters(
                "Modulus m must be > 1".to_string(),
            ));
        }
        if p == 0 {
            return Err(CryptoError::InvalidParameters(
                "Number of equations p must be > 0".to_string(),
            ));
        }
        if q < p {
            // While possible, the paper implies p < q for solvability guarantee method
            // Let's allow q=p for now, but q<p is problematic.
            return Err(CryptoError::InvalidParameters(
                "Number of variables q must be >= p".to_string(),
            ));
        }

        let ring = Ring::try_with(m)?;
        let mut rng = StdRng::seed_from_u64(seed);

        // Generate matrix a (p x q) with rank p
        let a_matrix: Matrix;
        let mut attempts_a = 0;
        loop {
            if attempts_a > 100 {
                return Err(CryptoError::SetupFailed(
                    "Failed to generate matrix A with rank p after multiple attempts".to_string(),
                ));
            }
            let mut temp_a = vec![vec![0; q]; p];
            for row in temp_a.iter_mut() {
                for val in row.iter_mut() {
                    *val = (rng.random::<u64>() % m) as i64; // Use rng.random()
                }
            }
            match matrix_rank(&temp_a, &ring) {
                Ok(rank) => {
                    if rank == p {
                        a_matrix = temp_a;
                        break;
                    } else {
                        attempts_a += 1;
                    }
                }
                Err(e) => {
                    return Err(CryptoError::SetupFailed(format!(
                        "Error during rank calculation for matrix A: {}",
                        e
                    )));
                }
            }
        }

        // Generate invertible matrix b (p x p) and its inverse b_inv
        let b_matrix: Matrix;
        let b_inv_matrix: Matrix;
        let mut attempts_b = 0;
        loop {
            if attempts_b > 100 {
                return Err(CryptoError::SetupFailed(
                    "Failed to generate invertible matrix B after multiple attempts".to_string(),
                ));
            }
            let mut temp_b = vec![vec![0; p]; p];
            for row in temp_b.iter_mut() {
                for val in row.iter_mut() {
                    *val = (rng.random::<u64>() % m) as i64; // Use rng.random()
                }
            }
            match matrix_inverse(&temp_b, &ring) {
                Ok(inv) => {
                    b_matrix = temp_b;
                    b_inv_matrix = inv;
                    break;
                }
                Err(_) => {
                    attempts_b += 1;
                }
            }
        }

        // Generate constant vectors a_inner, a_outer (p x 1)
        let mut a_inner = vec![0; p];
        let mut a_outer = vec![0; p];
        for i in 0..p {
            a_inner[i] = (rng.random::<u64>() % m) as i64; // Use rng.random()
            a_outer[i] = (rng.random::<u64>() % m) as i64; // Use rng.random()
        }

        // Assemble structs
        let shared_params = SharedParams { m, ring, p, q };
        let encryption_params = EncryptionParams {
            a: a_matrix,
            b: b_matrix,
            a_inner: a_inner.clone(),
            a_outer: a_outer.clone(),
        };

        let decryption_secrets = DecryptionSecrets {
            b_inv: b_inv_matrix,
            a_inner,
            a_outer,
        };

        let public_key = PublicKey {
            shared: shared_params,
            encryption_params,
        };

        let private_key = PrivateKey {
            public_key,
            decryption_secrets,
        };

        Ok(private_key)
    }

    /// Exports the private key to a JSON string.
    pub fn to_json(&self) -> Result<String, CryptoError> {
        serde_json::to_string(self).map_err(|e| {
            CryptoError::SerializationError(format!("PrivateKey JSON export failed: {}", e))
        })
    }

    /// Imports a private key from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, CryptoError> {
        let mut key: PrivateKey = serde_json::from_str(json_str).map_err(|e| {
            CryptoError::SerializationError(format!("PrivateKey JSON import failed: {}", e))
        })?;
        key.public_key.shared.reconstruct_ring()?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (keypair)
    use crate::system::matrix_ops::{identity_matrix, matrix_mul}; // Corrected path

    const TEST_M: u64 = 25; // Example modulus
    const TEST_P: usize = 2; // Example block size
    const TEST_Q: usize = 4; // Example variable count
    const TEST_SEED: u64 = 42; // Example seed

    #[test]
    fn test_key_generation_valid() {
        let result = PrivateKey::generate(TEST_M, TEST_P, TEST_Q, TEST_SEED);
        assert!(result.is_ok());

        let private_key = result.unwrap();

        // Check dimensions
        let pk = &private_key.public_key;
        let ds = &private_key.decryption_secrets;

        assert_eq!(pk.shared.m, TEST_M);
        assert_eq!(pk.shared.p, TEST_P);
        assert_eq!(pk.shared.q, TEST_Q);
        // Ring validity checked by generation success

        assert_eq!(pk.encryption_params.a.len(), TEST_P);
        assert_eq!(pk.encryption_params.a[0].len(), TEST_Q);
        assert_eq!(pk.encryption_params.b.len(), TEST_P);
        assert_eq!(pk.encryption_params.b[0].len(), TEST_P);
        assert_eq!(pk.encryption_params.a_inner.len(), TEST_P);
        assert_eq!(pk.encryption_params.a_outer.len(), TEST_P);

        assert_eq!(ds.b_inv.len(), TEST_P);
        assert_eq!(ds.b_inv[0].len(), TEST_P);
        assert_eq!(ds.a_inner.len(), TEST_P);
        assert_eq!(ds.a_outer.len(), TEST_P);

        // Check a_inner and a_outer consistency
        assert_eq!(pk.encryption_params.a_inner, ds.a_inner);
        assert_eq!(pk.encryption_params.a_outer, ds.a_outer);

        // Verify B * B_inv = I (mod m) - Restore this check
        let b_mult_b_inv = matrix_mul(&pk.encryption_params.b, &ds.b_inv, &pk.shared.ring)
            .expect("Matrix multiplication failed during test");
        let identity = identity_matrix(TEST_P);
        assert_eq!(b_mult_b_inv, identity, "B * B_inv should be identity");
    }

    #[test]
    fn test_key_generation_invalid_params() {
        assert!(PrivateKey::generate(1, TEST_P, TEST_Q, TEST_SEED).is_err()); // m <= 1
        assert!(PrivateKey::generate(TEST_M, 0, TEST_Q, TEST_SEED).is_err()); // p = 0
        assert!(PrivateKey::generate(TEST_M, TEST_P, 1, TEST_SEED).is_err()); // q < p
    }

    #[test]
    fn test_private_key_serialization_deserialization() {
        let original_key = PrivateKey::generate(TEST_M, TEST_P, TEST_Q, TEST_SEED).unwrap();

        let json_str = original_key.to_json().unwrap();
        let deserialized_key_result = PrivateKey::from_json(&json_str);

        assert!(deserialized_key_result.is_ok());
        let deserialized_key = deserialized_key_result.unwrap();

        // Compare fields (Ring is reconstructed, not directly compared)
        assert_eq!(
            original_key.public_key.shared.m,
            deserialized_key.public_key.shared.m
        );
        assert_eq!(
            original_key.public_key.shared.p,
            deserialized_key.public_key.shared.p
        );
        assert_eq!(
            original_key.public_key.shared.q,
            deserialized_key.public_key.shared.q
        );
        assert_eq!(deserialized_key.public_key.shared.ring.modulus(), TEST_M);

        assert_eq!(
            original_key.public_key.encryption_params,
            deserialized_key.public_key.encryption_params
        );
        assert_eq!(
            original_key.decryption_secrets,
            deserialized_key.decryption_secrets
        );
    }

    #[test]
    fn test_public_key_serialization_deserialization() {
        let private_key = PrivateKey::generate(TEST_M, TEST_P, TEST_Q, TEST_SEED).unwrap();
        let original_key = private_key.public_key; // Clone the public part

        let json_str = original_key.to_json().unwrap();
        let deserialized_key_result = PublicKey::from_json(&json_str);

        assert!(deserialized_key_result.is_ok());
        let deserialized_key = deserialized_key_result.unwrap();

        // Compare fields
        assert_eq!(original_key.shared.m, deserialized_key.shared.m);
        assert_eq!(original_key.shared.p, deserialized_key.shared.p);
        assert_eq!(original_key.shared.q, deserialized_key.shared.q);
        assert_eq!(deserialized_key.shared.ring.modulus(), TEST_M);

        assert_eq!(
            original_key.encryption_params,
            deserialized_key.encryption_params
        );
    }
}
