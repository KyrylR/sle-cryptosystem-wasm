use crate::errors::SLECryptoError;
use crate::keypair::helper::{map_matrix, map_vector};
use crate::keypair::shared_params::SharedParams;
use crate::preset::encoding_table::INDEX_TO_BASE64_CHAR_MAP;
use crate::ring::matrix_ops::{
    identity_matrix, matrix_inverse, matrix_mul, matrix_vector_mul, vector_add, vector_sub,
};
use crate::ring::{gcd, Matrix, Ring, Vector};
use crate::sle::{modinv, solve_system};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub shared_params: SharedParams,
    pub matrix_A: GoodMatrix,
    pub matrix_A_bar: Matrix,
    pub matrix_B_inv: Matrix,
    pub vector_A_bar_inner: Vector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub good: GoodMatrix,
    pub matrix_A_factored: Matrix,
    pub matrix_A_bar_factored: Matrix,
    pub vector_A_bar_inner_factored: Vector,
}

/// A full‐row‐rank p×q matrix A together with
/// 1) one invertible p×p minor (indices),
/// 2) its inverse mod m.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoodMatrix {
    pub A: Matrix,              // p×q
    pub minor_cols: Vec<usize>, // length = p
    pub A1inv: Matrix,          // p×p inverse mod m
}

/// The result of key‐generation:
///  - `good` is your GoodMatrix = (A, minor_cols, A1inv)
///  - `B_eff` and `B_eff_inv` are the r‐fold products of your B_i’s
///  - `a_outer` is the final shift vector (= a_inner for L_bar)
///  - `A_bar = B_eff * A` is the p×q linear part of L_bar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyComponents {
    pub good: GoodMatrix,
    pub B_eff: Matrix,
    pub B_eff_inv: Matrix,
    pub a_outer: Vector,
    pub A_bar: Matrix,
    pub a_inner: Vector,
}

impl PrivateKey {
    pub fn try_with(shared_params: SharedParams) -> Result<Self, SLECryptoError> {
        let key_components = generate_key_components(&shared_params, 2)?;

        Ok(Self {
            shared_params,
            matrix_A: key_components.good,
            matrix_A_bar: key_components.A_bar,
            matrix_B_inv: key_components.B_eff_inv,
            vector_A_bar_inner: key_components.a_inner,
        })
    }

    pub fn get_public_key(&self) -> Result<PublicKey, SLECryptoError> {
        let shared_params = &self.shared_params;
        let inner_structure = &shared_params.inner_structure;

        // 1. Map from Z_k to G_m using inner_structure.map_into
        let map_zk_to_gm = |val| inner_structure.map_into(val);
        let matrix_a_gm = map_matrix(&self.matrix_A.A, &map_zk_to_gm);
        let matrix_a_bar_gm = map_matrix(&self.matrix_A_bar, &map_zk_to_gm);
        let vector_A_bar_inner_gm = map_vector(&self.vector_A_bar_inner, &map_zk_to_gm);

        // 2. Map from G_m to Gm/ksi using shared_params.map_into_pub
        let map_gm_to_gm_ksi = |val| shared_params.map_into_pub(val);
        let matrix_a_factored = map_matrix(&matrix_a_gm, &map_gm_to_gm_ksi);
        let matrix_a_bar_factored = map_matrix(&matrix_a_bar_gm, &map_gm_to_gm_ksi);
        let vector_a_bar_inner_factored = map_vector(&vector_A_bar_inner_gm, &map_gm_to_gm_ksi);

        Ok(PublicKey {
            good: self.matrix_A.clone(),
            matrix_A_factored: matrix_a_factored,
            matrix_A_bar_factored: matrix_a_bar_factored,
            vector_A_bar_inner_factored: vector_a_bar_inner_factored,
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

        // 3) remove the a_inner shift:  d1' = d1 − a_inner
        let d1prime = vector_sub(&d1, &self.vector_A_bar_inner, ring)?;

        // 4) apply B_eff⁻¹:  tmp = B_eff⁻¹ · d1'
        let tmp = matrix_vector_mul(&self.matrix_B_inv, &d1prime, ring)?;

        // 5) subtract d to get A·x_bar = v
        let v_zm = vector_sub(&tmp, &d, ring)?;

        Ok(v_zm)
    }
}

/// Randomly generate a p×q matrix A over Z/m with the property that
///  - rank(A)=p (equivalently A * y≡0 has only the trivial solution)
pub fn make_good_matrix(p: usize, q: usize, ring: &Ring) -> Result<GoodMatrix, SLECryptoError> {
    let m = ring.modulus() as i64;
    let mut attempts = 0;

    loop {
        attempts += 1;
        if attempts > 100_000 {
            return Err(SLECryptoError::InternalError(
                "Could not generate full‐row‐rank A with invertible minor".into(),
            ));
        }

        // 1) pick random p×q in Z/m
        let mut A = vec![vec![0i64; q]; p];
        for row in &mut A {
            for x in row.iter_mut() {
                *x = ring.normalize(rand::random::<i64>());
            }
        }

        // 2) test row‐independence by checking null‐space of A^T
        let AT: Matrix = (0..q).map(|j| (0..p).map(|i| A[i][j]).collect()).collect();
        let null = solve_system(&AT, m);
        let rows_indep = null.iter().all(|v| v.iter().all(|&x| x.rem_euclid(m) == 0));
        if !rows_indep {
            continue;
        }

        // 3) find one p‐subset of columns whose p×p minor is invertible mod m
        let mut chosen: Vec<usize> = Vec::new();
        for cols in combinations(q, p) {
            // build the p×p submatrix on cols
            let mut sub = vec![vec![0i64; p]; p];
            for (r, &c) in cols.iter().enumerate() {
                for rr in 0..p {
                    sub[rr][r] = A[rr][c].rem_euclid(m);
                }
            }
            let d = det_mod(&sub, m);
            if gcd(d, m) == 1 {
                chosen = cols;
                break;
            }
        }
        if chosen.len() != p {
            continue;
        }

        // 4) build that submatrix A1 and invert it by Gauss–Jordan
        let mut A1 = vec![vec![0i64; p]; p];
        for i in 0..p {
            for (j, &c) in chosen.iter().enumerate() {
                A1[i][j] = A[i][c].rem_euclid(m);
            }
        }
        gauss_jordan_inv(&mut A1, m);

        // 5) we now have A, minor cols and A1inv
        return Ok(GoodMatrix {
            A,
            minor_cols: chosen,
            A1inv: A1,
        });
    }
}

/// Compute det(A) mod m for an n×n matrix A (in ℤ/m), returning a value in [0..m).
/// If we ever fail to find an invertible pivot, we return 0 (so gcd(det,m)>1).
pub fn det_mod(A: &[Vec<i64>], m: i64) -> i64 {
    let n = A.len();
    assert!(A.iter().all(|row| row.len() == n));
    // copy into working matrix, reduce mod m
    let mut a: Vec<Vec<i64>> = A
        .iter()
        .map(|row| row.iter().map(|&x| x.rem_euclid(m)).collect())
        .collect();
    let mut det: i64 = 1;
    let mut sign: i64 = 1;

    for i in 0..n {
        // find pivot row with a[j][i] != 0 mod m
        let mut piv = None;
        for j in i..n {
            if a[j][i].rem_euclid(m) != 0 {
                piv = Some(j);
                break;
            }
        }
        let j = match piv {
            None => {
                // zero column ⇒ det≡0
                return 0;
            }
            Some(j) => j,
        };
        if j != i {
            a.swap(i, j);
            sign = -sign;
        }
        let p = a[i][i].rem_euclid(m);
        // if pivot not invertible, det shares gcd with m ⇒ not a unit
        let inv = match modinv(p, m) {
            None => return 0,
            Some(v) => v,
        };
        // accumulate det *= p
        det = (det * p).rem_euclid(m);
        // eliminate below
        for row in (i + 1)..n {
            let factor = (a[row][i].rem_euclid(m) * inv).rem_euclid(m);
            if factor != 0 {
                for col in i..n {
                    let v = a[row][col] - factor * a[i][col];
                    a[row][col] = v.rem_euclid(m);
                }
            }
        }
    }

    det = det.rem_euclid(m) * sign;
    det.rem_euclid(m)
}

/// Generate all k‐combinations of {0,1,…,n−1} in lex order.
/// Returns a Vec of Vec<usize>, each inner Vec has length k.
pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut res = Vec::new();
    if k > n {
        return res;
    }
    // first combination [0,1,…,k-1]
    let mut comb: Vec<usize> = (0..k).collect();
    loop {
        res.push(comb.clone());
        // find rightmost position we can bump
        let mut i = k;
        while i > 0 {
            i -= 1;
            if comb[i] != i + n - k {
                break;
            }
            if i == 0 {
                // we are done
                return res;
            }
        }
        // bump comb[i]
        comb[i] += 1;
        // reset the tail
        for j in i + 1..k {
            comb[j] = comb[j - 1] + 1;
        }
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
pub fn generate_key_components(
    shared: &SharedParams,
    r: usize,
) -> Result<KeyComponents, SLECryptoError> {
    if r == 0 {
        return Err(SLECryptoError::InvalidParameters(
            "r must be at least 1".into(),
        ));
    }

    let ring = &shared.inner_structure.ring;
    let p = shared.equation_count;
    let q = shared.variables_count;

    // ----------------------------------------------------------------
    // 1) full‐row‐rank A and its invertible minor
    let good = make_good_matrix(p, q, ring)?;

    // ----------------------------------------------------------------
    // 2) pick r random invertible B_i (p×p) and store their inverses
    let mut Bs = Vec::with_capacity(r);
    let mut Binvs = Vec::with_capacity(r);
    for _ in 0..r {
        let (B, Binv) = make_invertible_pp(p, ring)?;
        Bs.push(B);
        Binvs.push(Binv);
    }

    // ----------------------------------------------------------------
    // 3) r+1 random shift‐vectors a_1…a_{r+1}
    let mut shifts = Vec::with_capacity(r + 1);
    for _ in 0..(r + 1) {
        let v: Vector = (0..p).map(|_| ring.normalize(rand::random())).collect();
        shifts.push(v);
    }

    // ----------------------------------------------------------------
    // 4) B_eff = B_r · B_{r-1} · … · B_1
    let B_eff = {
        let mut acc = identity_matrix(p);
        for B in &Bs {
            acc = matrix_mul(B, &acc, ring)
                .map_err(|e| SLECryptoError::InternalError(format!("B_eff mul failed: {}", e)))?;
        }
        acc
    };

    // ----------------------------------------------------------------
    // 5) B_eff_inv = B_1^{-1} · … · B_r^{-1}
    let B_eff_inv = {
        let mut acc = identity_matrix(p);
        for Binv in &Binvs {
            acc = matrix_mul(&acc, Binv, ring).map_err(|e| {
                SLECryptoError::InternalError(format!("B_eff_inv mul failed: {}", e))
            })?;
        }
        acc
    };

    // ----------------------------------------------------------------
    // 6) a_outer = a_{r+1} + ∑_{j=1..r} (B_r…B_{j+1}) · a_j
    let mut a_outer = shifts[r].clone();
    // suffix = product B_r … B_{j+1}, start at the identity
    let mut suffix = identity_matrix(p);
    // walk j = r−1, r−2, …, 0
    for j in (0..r).rev() {
        // add suffix · shifts[j]
        let term = matrix_vector_mul(&suffix, &shifts[j], ring)
            .map_err(|e| SLECryptoError::InternalError(format!("a_outer term failed: {}", e)))?;
        a_outer = vector_add(&a_outer, &term, ring)
            .map_err(|e| SLECryptoError::InternalError(format!("a_outer add failed: {}", e)))?;
        // extend suffix ← B_{j+1} · suffix
        suffix = matrix_mul(&Bs[j], &suffix, ring)
            .map_err(|e| SLECryptoError::InternalError(format!("suffix mul failed: {}", e)))?;
    }

    // ----------------------------------------------------------------
    // 7) Build A_bar = B_eff · A
    let A_bar = matrix_mul(&B_eff, &good.A, ring)
        .map_err(|e| SLECryptoError::InternalError(format!("A_bar mul failed: {}", e)))?;

    // a_outer is now the constant term of L_bar(x) = A_bar·x + a_outer
    let a_inner = a_outer.clone();

    Ok(KeyComponents {
        good,
        B_eff,
        B_eff_inv,
        a_outer,
        A_bar,
        a_inner,
    })
}

/// In‐place Gauss–Jordan elimination to turn `mat` into its inverse
/// over Z/m.  Panics if a pivot is ever non‐invertible.
fn gauss_jordan_inv(mat: &mut Matrix, m: i64) {
    let n = mat.len();
    // append identity in a separate buffer
    let mut inv = vec![vec![0i64; n]; n];
    for i in 0..n {
        inv[i][i] = 1;
    }

    for i in 0..n {
        // pivot search
        let mut pivot = i;
        while pivot < n && mat[pivot][i].rem_euclid(m) == 0 {
            pivot += 1;
        }
        assert!(pivot < n, "Minor wasn’t actually invertible");
        mat.swap(i, pivot);
        inv.swap(i, pivot);

        // normalize row i
        let ai = mat[i][i].rem_euclid(m);
        let inv_ai = modinv(ai, m).expect("Pivot not invertible even though det was");
        for c in 0..n {
            mat[i][c] = (mat[i][c] * inv_ai).rem_euclid(m);
            inv[i][c] = (inv[i][c] * inv_ai).rem_euclid(m);
        }

        // eliminate all other rows
        for r in 0..n {
            if r == i {
                continue;
            }
            let factor = mat[r][i].rem_euclid(m);
            if factor != 0 {
                for c in 0..n {
                    mat[r][c] = (mat[r][c] - factor * mat[i][c]).rem_euclid(m);
                    inv[r][c] = (inv[r][c] - factor * inv[i][c]).rem_euclid(m);
                }
            }
        }
    }

    *mat = inv;
}
