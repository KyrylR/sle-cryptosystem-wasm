use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crate::errors::SLECryptoError;
use crate::keypair::shared_params::SharedParams;
use crate::ring::matrix_ops::{identity_matrix, matrix_inverse, matrix_mul, matrix_rank, matrix_vector_mul, vector_add, vector_sub};
use crate::ring::{Matrix, Vector};

use crate::keypair::helper::{map_matrix, map_vector};
use rand::random;
use serde::{Deserialize, Serialize};
use crate::preset::encoding_table::INDEX_TO_BASE64_CHAR_MAP;

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKey {
    pub shared_params: SharedParams,
    pub matrix_A: Matrix,
    pub matrix_B: Matrix,
    pub matrix_B_inv: Matrix,
    pub vector_a: Vector,
    pub vector_Ba: Vector,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub matrix_A_factored: Matrix,
    pub matrix_B_factored: Matrix,
    pub vector_Ba_factored: Vector,
}

impl PrivateKey {
    pub fn try_with(shared_params: SharedParams) -> Result<Self, SLECryptoError> {
        let (a_matrix, b_eff_matrix, b_eff_inv_matrix, a_inner_eff, a_outer_eff) =
            generate_key_components(&shared_params, 2)?;

        Ok(Self {
            shared_params,
            matrix_A: a_matrix,
            matrix_B: b_eff_matrix,
            matrix_B_inv: b_eff_inv_matrix,
            vector_a: a_inner_eff,
            vector_Ba: a_outer_eff,
        })
    }

    pub fn get_public_key(&self) -> Result<PublicKey, SLECryptoError> {
        let shared_params = &self.shared_params;
        let inner_structure = &shared_params.inner_structure;

        // 1. Map from Z_k to G_m using inner_structure.map_into
        let map_zk_to_gm = |val| inner_structure.map_into(val);
        let matrix_a_gm = map_matrix(&self.matrix_A, &map_zk_to_gm);
        let matrix_b_gm = map_matrix(&self.matrix_B, &map_zk_to_gm);
        let vector_ba_gm = map_vector(&self.vector_Ba, &map_zk_to_gm);

        // 2. Map from G_m to Gm/ksi using shared_params.map_into_pub
        let map_gm_to_gm_ksi = |val| shared_params.map_into_pub(val);
        let matrix_a_factored = map_matrix(&matrix_a_gm, &map_gm_to_gm_ksi);
        let matrix_b_factored = map_matrix(&matrix_b_gm, &map_gm_to_gm_ksi);
        let vector_ba_factored = map_vector(&vector_ba_gm, &map_gm_to_gm_ksi);

        Ok(PublicKey {
            matrix_A_factored: matrix_a_factored,
            matrix_B_factored: matrix_b_factored,
            vector_Ba_factored: vector_ba_factored,
        })
    }

    pub fn decrypt(&self, ciphertext: String) -> Result<String, SLECryptoError> {
        let encrypted_blocks: Vec<(Vector, Vector)> = serde_json::from_str(&ciphertext)?;

        // Decrypt each block
        let mut decrypted_indices: Vec<i64> = Vec::new();
        for block_pair in encrypted_blocks {
            let decrypted_block = self.decrypt_block(block_pair)?;
            decrypted_indices.extend(decrypted_block);
        }

        // Convert indices to Base64 characters
        let base64_chars: Vec<char> = decrypted_indices
            .into_iter()
            .map(|index| INDEX_TO_BASE64_CHAR_MAP[&(index as u8)]) // Map i64 index to u8, then to char
            .collect();

        // Reconstruct Base64 string and remove padding
        let base64_string_with_padding: String = base64_chars.into_iter().collect();
        let base64_string = base64_string_with_padding.trim_end_matches('=').to_string();

        // Decode Base64 string to original bytes
        let decoded_bytes = STANDARD.decode(&base64_string)
            .map_err(|e| SLECryptoError::InternalError(format!("Base64 decoding failed: {}", e)))?;

        // Convert bytes to UTF-8 string
        String::from_utf8(decoded_bytes)
            .map_err(|e| SLECryptoError::InternalError(format!("Failed to convert decoded bytes to UTF-8: {}", e)))
    }

    pub fn decrypt_block(&self, block: (Vector, Vector)) -> Result<Vector, SLECryptoError> {
        let map_gm_ksi_to_gm = |val| self.shared_params.map_pub_back(val);
        let map_gm_to_zm = |val| self.shared_params.inner_structure.map_back(val);

        // 1. Map from Gm/ksi to G_m
        let d_gm = map_vector(&block.0, &map_gm_ksi_to_gm);
        let d1_gm = map_vector(&block.1, &map_gm_ksi_to_gm);

        // 2. Map from G_m to Zm
        let d = map_vector(&d_gm, &map_gm_to_zm);
        let d1 = map_vector(&d1_gm, &map_gm_to_zm);

        let ring = &self.shared_params.inner_structure.ring;

        // 1. Calculate intermediate = B_inv * (d1 - vector_ba)
        let d1_minus_outer_zm = vector_sub(&d1, &self.vector_Ba, &ring)?;
        let b_inv_mult_zm = matrix_vector_mul(&self.matrix_B_inv, &d1_minus_outer_zm, &ring)?;

        // 2. multiply by A: result is A * x + A * a_bar = v + d
        let a_mut_sum = matrix_vector_mul(&self.matrix_A, &b_inv_mult_zm, &ring)?;

        // 3. Subtract d: result is A * x_bar = v
        let v_zm = vector_sub(&a_mut_sum, &d, &ring)?;

        Ok(v_zm)
    }
}

/// Private helper function to generate the core components for key generation based on 'r' steps.
///
/// Generates matrix A, sequences Bi and ai, and calculates effective B, B_inv, a_inner, a_outer.
fn generate_key_components(
    shared_params: &SharedParams,
    r: usize,
) -> Result<(Matrix, Matrix, Matrix, Vector, Vector), SLECryptoError> {
    if r == 0 {
        return Err(SLECryptoError::InvalidParameters(
            "Number of transformation steps 'r' must be at least 1".to_string(),
        ));
    }

    let ring = &shared_params.inner_structure.ring;
    let equation_count = shared_params.equation_count;
    let variables_count = shared_params.variables_count;

    // 1. Generate matrix A (p x q) with rank p over Z_m
    let a_matrix: Matrix;
    let mut attempts_a = 0;
    loop {
        if attempts_a > 100 {
            return Err(SLECryptoError::InternalError(
                "Failed to generate matrix A with rank p after multiple attempts".to_string(),
            ));
        }
        let mut temp_a = vec![vec![0; variables_count]; equation_count];
        for row in temp_a.iter_mut() {
            for val in row.iter_mut() {
                *val = ring.normalize(random::<i64>());
            }
        }
        match matrix_rank(&temp_a, ring) {
            Ok(rank) => {
                if rank == equation_count {
                    a_matrix = temp_a;
                    break;
                } else {
                    attempts_a += 1;
                }
            }
            Err(e) => {
                return Err(SLECryptoError::InternalError(format!(
                    "Error during rank calculation for matrix A: {}",
                    e
                )));
            }
        }
    }

    // Helper function to generate an invertible p x p matrix and its inverse
    let generate_invertible_matrix = || -> Result<(Matrix, Matrix), SLECryptoError> {
        let mut attempts = 0;
        loop {
            if attempts > 100 {
                return Err(SLECryptoError::InternalError(
                    "Failed to generate invertible matrix after multiple attempts".to_string(),
                ));
            }
            let mut temp_b = vec![vec![0; equation_count]; equation_count];
            for row in temp_b.iter_mut() {
                for val in row.iter_mut() {
                    *val = ring.normalize(random::<i64>());
                }
            }
            match matrix_inverse(&temp_b, ring) {
                Ok(inv) => return Ok((temp_b, inv)),
                Err(_) => attempts += 1,
            }
        }
    };

    // 2. Generate r pairs of (Bi, Bi_inv)
    let mut b_matrices = Vec::with_capacity(r);
    let mut b_inv_matrices = Vec::with_capacity(r);
    for _ in 0..r {
        let (b, b_inv) = generate_invertible_matrix()?;
        b_matrices.push(b);
        b_inv_matrices.push(b_inv);
    }

    // 3. Generate r+2 vectors a0, a1, ..., ar, ar+1
    let mut a_vectors = Vec::with_capacity(r + 2);
    for _ in 0..(r + 2) {
        let mut a_vec = vec![0; equation_count];
        for val in a_vec.iter_mut() {
            *val = ring.normalize(random::<i64>());
        }
        a_vectors.push(a_vec);
    }

    // 4. Calculate effective parameters B_eff, B_eff_inv, a_inner, a_outer

    // B_eff = Br * ... * B1
    let mut b_eff_matrix = b_matrices[0].clone();
    for i in 1..r {
        b_eff_matrix = matrix_mul(&b_matrices[i], &b_eff_matrix, ring).map_err(|e| {
            SLECryptoError::InternalError(format!("B_eff calculation failed: {}", e))
        })?;
    }

    // B_eff_inv = B1_inv * ... * Br_inv
    let mut b_eff_inv_matrix = b_inv_matrices[0].clone();
    for i in 1..r {
        b_eff_inv_matrix =
            matrix_mul(&b_eff_inv_matrix, &b_inv_matrices[i], ring).map_err(|e| {
                SLECryptoError::InternalError(format!("B_eff_inv calculation failed: {}", e))
            })?;
    }

    // a_inner = a0 (which is a_vectors[0])
    let a_inner_eff = a_vectors[0].clone();

    // a_outer = Sum_{j=1..r} (Br...B{j+1}) * aj + a{r+1}
    let mut a_outer_eff = a_vectors[r + 1].clone(); // Start with a_{r+1}
    let mut b_product_suffix = identity_matrix(equation_count);

    // Loop j from r down to 1
    for j in (1..=r).rev() {
        // b_product_suffix currently holds Br...B{j+1}
        let current_a = &a_vectors[j];
        let term = matrix_vector_mul(&b_product_suffix, current_a, ring).map_err(|e| {
            SLECryptoError::InternalError(format!(
                "a_outer calculation term failed (j={}): {}",
                j, e
            ))
        })?;

        a_outer_eff = vector_add(&a_outer_eff, &term, ring).map_err(|e| {
            SLECryptoError::InternalError(format!(
                "a_outer calculation add failed (j={}): {}",
                j, e
            ))
        })?;

        // Update suffix product for next iteration (j-1): Need Br...Bj
        // Pre-multiply by Bj (which is b_matrices[j-1])
        let b_j = &b_matrices[j - 1];
        b_product_suffix = matrix_mul(b_j, &b_product_suffix, ring).map_err(|e| {
            SLECryptoError::InternalError(format!(
                "a_outer calculation suffix product failed (j={}): {}",
                j, e
            ))
        })?;
    }

    Ok((
        a_matrix,
        b_eff_matrix,
        b_eff_inv_matrix,
        a_inner_eff,
        a_outer_eff,
    ))
}
