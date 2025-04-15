use crate::errors::SLECryptoError;
use crate::keypair::helper::{map_matrix, map_vector};
use crate::keypair::shared_params::SharedParams;
use crate::preset::encoding_table::INDEX_TO_BASE64_CHAR_MAP;
use crate::ring::matrix_ops::{
    identity_matrix, matrix_inverse, matrix_mul, matrix_vector_mul, vector_add, vector_sub,
};
use crate::ring::{Matrix, Ring, Vector};
use crate::sle::solve_system;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKey {
    pub shared_params: SharedParams,
    pub matrix_A: Matrix,
    pub matrix_B: Matrix,
    pub matrix_B_inv: Matrix,
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
        let (a_matrix, b_eff_matrix, b_eff_inv_matrix, a_outer_eff) =
            generate_key_components(&shared_params, 2)?;

        Ok(Self {
            shared_params,
            matrix_A: a_matrix,
            matrix_B: b_eff_matrix,
            matrix_B_inv: b_eff_inv_matrix,
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
        let base64_string: String = base64_chars.into_iter().collect();

        // Decode Base64 string to original bytes
        let decoded_bytes = STANDARD
            .decode(&base64_string)
            .map_err(|e| SLECryptoError::InternalError(format!("Base64 decoding failed: {}", e)))?;

        // Convert bytes to UTF-8 string
        String::from_utf8(decoded_bytes).map_err(|e| {
            SLECryptoError::InternalError(format!(
                "Failed to convert decoded bytes to UTF-8: {}",
                e
            ))
        })
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
        let d1_minus_outer_zm = vector_sub(&d1, &self.vector_Ba, ring)?;
        let b_inv_mult_zm = matrix_vector_mul(&self.matrix_B_inv, &d1_minus_outer_zm, ring)?;

        // 2. multiply by A: result is A * x + A * a_bar = v + d
        let a_mut_sum = matrix_vector_mul(&self.matrix_A, &b_inv_mult_zm, ring)?;

        // 3. Subtract d: result is A * x_bar = v
        let v_zm = vector_sub(&a_mut_sum, &d, ring)?;

        Ok(v_zm)
    }
}

/// Randomly generate a p×q matrix A over Z/m with the property that
///  - rank(A)=p (equivalently A * y≡0 has only the trivial solution)
fn make_good_matrix(p: usize, q: usize, ring: &Ring) -> Result<Matrix, SLECryptoError> {
    let m = ring.modulus();
    let mut attempts = 0;

    loop {
        attempts += 1;
        if attempts > 100000 {
            return Err(SLECryptoError::InternalError(
                "Could not generate A of full rank with an invertible p×p minor".into(),
            ));
        }

        let mut A: Matrix = vec![vec![0; q]; p];
        for row in &mut A {
            for cell in row.iter_mut() {
                *cell = ring.normalize(rand::random::<i64>());
            }
        }

        // solve one homogeneous system A * y = 0
        let null_of_A = solve_system(&A, m as i64);
        // if ns contains any nonzero vector => rows not independent
        let only_zero = null_of_A
            .iter()
            .all(|v| v.iter().all(|&x| x.rem_euclid(m as i64) == 0));

        if !only_zero {
            continue; // dependent rows, regenerate
        }
        return Ok(A);
    }
}

/// Helper: generate one random invertible p×p matrix (and its inverse)
fn make_invertible_pp(p: usize, ring: &Ring) -> Result<(Matrix, Matrix), SLECryptoError> {
    for _ in 0..1000 {
        // random p×p
        let mut M = vec![vec![0; p]; p];
        for row in &mut M {
            for x in row.iter_mut() {
                *x = ring.normalize(rand::random::<i64>());
            }
        }
        // try invert
        if let Ok(Minv) = matrix_inverse(&M, ring) {
            return Ok((M, Minv));
        }
    }
    Err(SLECryptoError::InternalError(
        "could not generate invertible p×p after 1000 tries".into(),
    ))
}

/// Private helper function to generate the core components for key generation based on 'r' steps.
///
/// Generates matrix A, sequences Bi and ai, and calculates effective B, B_inv, a_inner, a_outer.
fn generate_key_components(
    shared: &SharedParams,
    r: usize,
) -> Result<(Matrix, Matrix, Matrix, Vector), SLECryptoError> {
    if r == 0 {
        return Err(SLECryptoError::InvalidParameters(
            "r must be at least 1".into(),
        ));
    }
    let ring = &shared.inner_structure.ring;
    let p = shared.equation_count;
    let q = shared.variables_count;

    // 1) full‐rank A: p×q
    let A = make_good_matrix(p, q, ring)?;

    // 2) r random invertible p×p matrices B_i and their inverses
    let mut Bs = Vec::with_capacity(r);
    let mut Binvs = Vec::with_capacity(r);
    for _ in 0..r {
        let (B, b_inv) = make_invertible_pp(p, ring)?;
        Bs.push(B);
        Binvs.push(b_inv);
    }

    // 3) r+1 random shift‐vectors a_1…a_{r+1}
    let mut shifts = Vec::with_capacity(r + 1);
    for _ in 0..(r + 1) {
        let v: Vector = (0..p)
            .map(|_| ring.normalize(rand::random::<i64>()))
            .collect();
        shifts.push(v);
    }

    // 4) B_eff = B_r * B_{r-1} * … * B_1
    let B_eff = {
        let mut acc = identity_matrix(p);
        for Bi in &Bs {
            acc = matrix_mul(Bi, &acc, ring)
                .map_err(|e| SLECryptoError::InternalError(format!("B_eff mul failed: {}", e)))?;
        }
        acc
    };
    // 5) B_eff_inv = B_1^{-1} * … * B_r^{-1}
    let B_eff_inv = {
        let mut acc = identity_matrix(p);
        for Binv in &Binvs {
            acc = matrix_mul(&acc, Binv, ring).map_err(|e| {
                SLECryptoError::InternalError(format!("B_eff_inv mul failed: {}", e))
            })?;
        }
        acc
    };

    // 6) a_outer = a_{r+1} + sum_{j=1..r} (B_r … B_{j+1}) * a_j
    let mut a_out = shifts[r].clone(); // start with a_{r+1}
    let mut suffix = identity_matrix(p); // initially Br…B_{r+1}=I
    for j in (0..r).rev() {
        // prefix = B_r … B_{j+1}
        let aj = &shifts[j];
        let term = matrix_vector_mul(&suffix, aj, ring).map_err(|e| {
            SLECryptoError::InternalError(format!("a_out term failed j={}: {}", j, e))
        })?;
        a_out = vector_add(&a_out, &term, ring).map_err(|e| {
            SLECryptoError::InternalError(format!("a_out add failed j={}: {}", j, e))
        })?;
        // extend suffix ← B_{j+1} * suffix
        suffix = matrix_mul(&Bs[j], &suffix, ring).map_err(|e| {
            SLECryptoError::InternalError(format!("suffix mul failed j={}: {}", j, e))
        })?;
    }

    Ok((A, B_eff, B_eff_inv, a_out))
}
