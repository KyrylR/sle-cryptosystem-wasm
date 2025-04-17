use crate::errors::SLECryptoError;
use crate::gen_g::Isomorphism;
use crate::keypair::helper::{map_matrix, map_vector};
use crate::keypair::keys::PublicKey;
use crate::preset::encoding_table::BASE64_CHAR_TO_INDEX_MAP;
use crate::ring::Vector;
use crate::ring::matrix_ops::{identity_matrix, matrix_vector_mul, vector_add};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use rand::random;

use serde::{Deserialize, Serialize};
use serde_json;

/// Parameters shared for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedParams {
    /// Number of equations p in the linear systems, also the message block size.
    pub equation_count: usize,
    /// Number of variables q in the linear systems (typically q > p).
    pub variables_count: usize,
    /// Isomorphism for Z_k
    pub inner_structure: Isomorphism,
    /// Isomorphism for G_m
    pub outer_structure: Isomorphism,
    /// Built based on the `outer_structure`.
    /// 1. ksi_1_0 = gen_g_a = outer_structure.definite_string_{pos_a}
    /// 2. ksi_1_i = outer_structure.definite_string_{pos_a + i}, i = (1..m) % k
    pub ksi_1: Vector,
    /// Built based on the `ksi_1`.
    pub reverse_ksi_1: Vector,
}

impl SharedParams {
    /// Creates a new SharedParams instance with the given parameters.
    pub fn try_with(
        gen_g_a: u64,
        gen_g_c: u64,
        gen_g_l: u64,
        gen_g_k: u64,
        gen_g_seed: u64,
        equation_count: usize,
        variables_count: usize,
    ) -> Result<Self, SLECryptoError> {
        if gen_g_k == 0 || gen_g_a == 0 || gen_g_c == 0 || gen_g_l == 0 {
            return Err(SLECryptoError::InvalidParameters(
                "Gen G params must be > 0".to_string(),
            ));
        }

        if variables_count < equation_count {
            return Err(SLECryptoError::InvalidParameters(
                "Number of variables q must be >= p".to_string(),
            ));
        }

        if equation_count == 0 {
            return Err(SLECryptoError::InvalidParameters(
                "Number of equations p must be > 0".to_string(),
            ));
        }

        let modulus_k = gen_g_k;
        let isomorphism_zk = Isomorphism::gen_g(
            gen_g_a as i64,
            gen_g_c as i64,
            gen_g_l as i64,
            modulus_k as i64,
            gen_g_seed as i64,
        )?;

        let modulus_m = gen_g_k * gen_g_l;
        let isomorphism_zm = Isomorphism::gen_g(
            gen_g_a as i64,
            gen_g_c as i64,
            gen_g_l as i64,
            modulus_m as i64,
            gen_g_seed as i64,
        )?;

        let modulus_m_usize = modulus_m as usize;

        // Find the position of gen_g_a in the definite string of the outer structure
        let pos_a_opt = isomorphism_zm
            .definite_string
            .iter()
            .position(|&x| x == gen_g_a as i64);

        let pos_a = match pos_a_opt {
            Some(pos) => pos,
            None => {
                return Err(SLECryptoError::InternalError(
                    "gen_g_a not found in outer_structure.definite_string".to_string(),
                ));
            }
        };

        // Generate ksi_1 vector of size modulus_m
        let mut ksi_1 = vec![0i64; modulus_m_usize];
        ksi_1[0] = gen_g_a as i64; // As per comment: ksi_1_0 = gen_g_a

        for i in 1..modulus_m {
            let index = (pos_a + i as usize) % modulus_m_usize;
            ksi_1[i as usize] = isomorphism_zm.definite_string[index];
        }

        let mut reverse_ksi_1: Vector = vec![0; modulus_m_usize];
        for (i, &value) in ksi_1.iter().enumerate() {
            reverse_ksi_1[value as usize] = i as i64;
        }

        Ok(Self {
            equation_count,
            variables_count,
            inner_structure: isomorphism_zk,
            outer_structure: isomorphism_zm,
            ksi_1,
            reverse_ksi_1,
        })
    }

    pub fn map_into_pub(&self, value: i64) -> i64 {
        let normalized_value = self.outer_structure.ring.normalize(value);
        self.ksi_1[normalized_value as usize]
    }

    pub fn map_pub_back(&self, value: i64) -> i64 {
        let normalized_value = self.outer_structure.ring.normalize(value);
        self.reverse_ksi_1[normalized_value as usize]
    }

    pub fn encrypt(&self, public_key: &PublicKey, data: String) -> Result<String, SLECryptoError> {
        // 1. Pad the original data so its Base64 encoded length is a multiple of block_size
        let block_size = self.equation_count;
        let mut padded_data = data.into_bytes(); // Work with bytes for easier padding
        // Use a padding character unlikely to be confused with Base64's '='
        let padding_char = 0u8; // Null byte

        while STANDARD.encode(&padded_data).len() % block_size != 0 {
            padded_data.push(padding_char);
        }

        // 2. Prepare data for encryption: Base64 encode and map characters to indices
        let encoded_data = STANDARD.encode(&padded_data);
        let mut prepared_data: Vec<u8> = vec![0; encoded_data.len()];
        for (index, char) in encoded_data.chars().enumerate() {
            prepared_data[index] = BASE64_CHAR_TO_INDEX_MAP[&char]
        }

        // 3. Decompose prepared_data into blocks. Length is guaranteed to be multiple of block_size.
        let blocks: Vec<Vector> = prepared_data
            .chunks_exact(block_size)
            .map(|chunk| chunk.iter().map(|&byte| byte as i64).collect())
            .collect();

        // 4. Encrypt data using `encrypt_block` function
        let mut encrypted_blocks: Vec<(Vector, Vector)> = Vec::with_capacity(blocks.len());
        for block in blocks.iter() {
            encrypted_blocks.push(self.encrypt_block(public_key, block)?);
        }

        // 5. Combine blocks and using serde_json serialize them and return
        serde_json::to_string(&encrypted_blocks).map_err(|e| {
            SLECryptoError::InternalError(format!("Failed to serialize encrypted blocks: {}", e))
        })
    }

    /// Encrypts a message block `v` (elements in Zm) using the public key.
    ///
    /// # Arguments
    /// * `public_key`: The public key (components conceptually in Gm).
    /// * `v_zm`: The message block (vector of length `p`, elements in Zm).
    /// * `seed`: Seed to generate the random vector `a_bar`.
    ///
    /// # Returns
    /// The ciphertext block `(d, d1)` (vectors with elements in Gm) or a `CryptoError`.
    fn encrypt_block(
        &self,
        public_key: &PublicKey,
        block: &Vector,
    ) -> Result<(Vector, Vector), SLECryptoError> {
        // Ciphertext (d, d1) is in Gm (u32)
        if block.len() != self.equation_count {
            return Err(SLECryptoError::DimensionMismatch(format!(
                "Message block length ({}) must match parameter p ({})",
                block.len(),
                self.equation_count
            )));
        }

        // 1. Map from Gm/ksi to G_m
        let map_gm_ksi_to_gm = |val| self.map_pub_back(val);
        let matrix_a_gm = map_matrix(&public_key.matrix_A_factored, &map_gm_ksi_to_gm);
        let matrix_a_bar_gm = map_matrix(&public_key.matrix_A_bar_factored, &map_gm_ksi_to_gm);
        let vector_a_bar_inner_gm =
            map_vector(&public_key.vector_A_bar_inner_factored, &map_gm_ksi_to_gm);

        // 2. Map from G_m to Zm
        let map_gm_to_zm = |val| self.inner_structure.map_back(val);
        let matrix_a = map_matrix(&matrix_a_gm, &map_gm_to_zm);
        let matrix_a_bar = map_matrix(&matrix_a_bar_gm, &map_gm_to_zm);
        let vector_a_bar_inner = map_vector(&vector_a_bar_inner_gm, &map_gm_to_zm);

        let ring = &self.inner_structure.ring;
        
        // 3. Solve Ax = v (mod m) in Zm for a particular solution x_bar_zm
        let m = ring.modulus() as i64;

        // build RHS = b  (length p)
        let b_zm: Vec<i64> = block.iter().map(|&v| ring.normalize(v)).collect();

        // compute u = A1inv * b  (p×p times p×1)
        let mut u = vec![0i64; self.equation_count];
        for i in 0..self.equation_count {
            let mut s: i64 = 0;
            for j in 0..self.equation_count {
                s += public_key.good.A1inv[i][j] * b_zm[j];
            }
            u[i] = s.rem_euclid(m);
        }

        // scatter u into x at the minor positions:
        let mut x_bar_zm: Vector = vec![0; self.variables_count];
        for (i, &c) in public_key.good.minor_cols.iter().enumerate() {
            x_bar_zm[c] = u[i];
        }

        if x_bar_zm.len() != self.variables_count {
            return Err(SLECryptoError::InternalError(format!(
                "SLE solver returned solution of unexpected length {} (expected {})",
                x_bar_zm.len(),
                self.variables_count
            )));
        }

        // Generate random vector a_bar (q x 1) in Zm
        let mut a_bar_zm = vec![0; self.variables_count];
        for val in a_bar_zm.iter_mut() {
            *val = ring.normalize(random::<i64>());
        }

        // 4) d = A·a_bar  ∈ (Z/m)^p
        let d_zm = matrix_vector_mul(&matrix_a, &a_bar_zm, ring)?;

        // 5) d1 = A_bar·(x_bar+a_bar) + a_inner
        let xpa = vector_add(&x_bar_zm, &a_bar_zm, ring)?;
        let mut d1_zm = matrix_vector_mul(&matrix_a_bar, &xpa, ring)?;
        d1_zm = vector_add(&d1_zm, &vector_a_bar_inner, ring)?;

        // 6. Map final ciphertext d and d1
        let map_zk_to_gm = |val| self.inner_structure.map_into(val);
        let map_gm_to_gm_ksi = |val| self.map_into_pub(val);

        let d_gm = map_vector(&d_zm, &map_zk_to_gm);
        let d = map_vector(&d_gm, &map_gm_to_gm_ksi);

        let d1_gm = map_vector(&d1_zm, &map_zk_to_gm);
        let d1 = map_vector(&d1_gm, &map_gm_to_gm_ksi);

        Ok((d, d1))
    }
}
