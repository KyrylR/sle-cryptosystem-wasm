pub mod errors;
pub mod matrix_ops;
pub mod params;

use crate::ring::Ring;
use crate::sle::{Solution, solve as solve_sle}; // Alias solve
use errors::CryptoError;
use matrix_ops::{
    Matrix, Vector, matrix_inverse, matrix_rank, matrix_vector_mul, vector_add, vector_sub,
};
use params::{AliceSecret, BobPublic, SharedParams};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Sets up the shared, public, and secret parameters for the cryptosystem.
///
/// # Arguments
/// * `m`: Modulus for the ring Z_m.
/// * `p`: Number of equations (message block size).
/// * `q`: Number of variables (must be >= p for typical use).
/// * `seed`: A seed for deterministic random generation of matrices/vectors.
///
/// # Returns
/// A tuple `(SharedParams, AliceSecret, BobPublic)` or a `CryptoError`.
pub fn setup_shared(
    m: u64,
    p: usize,
    q: usize,
    seed: u64,
) -> Result<(SharedParams, AliceSecret, BobPublic), CryptoError> {
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

    // --- Generate Alice's components ---

    // Generate matrix a (p x q) with rank p
    let a_matrix: Matrix;
    let mut attempts_a = 0;
    loop {
        if attempts_a > 100 {
            // Avoid infinite loop
            return Err(CryptoError::SetupFailed(
                "Failed to generate matrix A with rank p after multiple attempts".to_string(),
            ));
        }
        let mut temp_a = vec![vec![0; q]; p];
        for row in temp_a.iter_mut() {
            for val in row.iter_mut() {
                *val = (rng.random::<u64>() % m) as i64;
            }
        }
        // Check rank
        match matrix_rank(&temp_a, &ring) {
            Ok(rank) => {
                if rank == p {
                    a_matrix = temp_a;
                    break; // Found matrix A with rank p
                } else {
                    attempts_a += 1;
                    continue; // Try generating a new A
                }
            }
            Err(e) => {
                // Error during rank calculation, potentially due to ring issues
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
    let mut attempts = 0;
    loop {
        if attempts > 100 {
            // Avoid infinite loop
            return Err(CryptoError::SetupFailed(
                "Failed to generate invertible matrix B after multiple attempts".to_string(),
            ));
        }
        let mut temp_b = vec![vec![0; p]; p];
        for row in temp_b.iter_mut() {
            for val in row.iter_mut() {
                *val = (rng.random::<u64>() % m) as i64;
            }
        }
        // Try to invert B
        match matrix_inverse(&temp_b, &ring) {
            Ok(inv) => {
                b_matrix = temp_b;
                b_inv_matrix = inv;
                break; // Found invertible B
            }
            Err(_) => {
                attempts += 1;
                continue; // Try generating a new B
            }
        }
    }

    // Generate constant vectors a_inner, a_outer (p x 1)
    let mut a_inner = vec![0; p];
    let mut a_outer = vec![0; p];
    for i in 0..p {
        a_inner[i] = (rng.random::<u64>() % m) as i64;
        a_outer[i] = (rng.random::<u64>() % m) as i64;
    }

    // --- Assemble structs ---
    let shared_params = SharedParams { m, ring, p, q };
    let alice_secret = AliceSecret {
        b_inv: b_inv_matrix,
        a_inner: a_inner.clone(),
        a_outer: a_outer.clone(),
    };
    let bob_public = BobPublic {
        a: a_matrix,
        b: b_matrix,
        a_inner,
        a_outer,
    };

    Ok((shared_params, alice_secret, bob_public))
}

/// Encrypts a message block `v` using Bob's public parameters.
///
/// # Arguments
/// * `shared`: Shared parameters.
/// * `public`: Bob's public parameters received from Alice.
/// * `v`: The message block (vector of length `p`).
/// * `seed`: Seed to generate the random vector `a_bar`. Using a seed makes
///           encryption deterministic for testing/debugging, use a real RNG in practice.
///
/// # Returns
/// The ciphertext block `(d, d1)` or a `CryptoError`.
pub fn encrypt(
    shared: &SharedParams,
    public: &BobPublic,
    v: &Vector,
    seed: u64,
) -> Result<(Vector, Vector), CryptoError> {
    if v.len() != shared.p {
        return Err(CryptoError::DimensionMismatch(format!(
            "Message block length ({}) must match parameter p ({})",
            v.len(),
            shared.p
        )));
    }

    let mut rng = StdRng::seed_from_u64(seed);

    // Generate random vector a_bar (q x 1)
    let mut a_bar = vec![0; shared.q];
    for val in a_bar.iter_mut() {
        *val = (rng.random::<u64>() % shared.m) as i64;
    }

    // 1. Solve Ax = v (mod m) for a particular solution x_bar
    let x_bar = match solve_sle(&public.a, v, shared.m)? {
        Solution::Unique(sol) => sol,
        Solution::Infinite(sol, _) => sol, // Pick the particular solution
        Solution::NoSolution => {
            return Err(CryptoError::EncryptionFailed(
                "System Ax=v has no solution for the given message block and matrix A".to_string(),
            ));
        }
    };

    if x_bar.len() != shared.q {
        return Err(CryptoError::InternalError(format!(
            "SLE solver returned solution of unexpected length {} (expected {})",
            x_bar.len(),
            shared.q
        )));
    }

    // 2. Calculate d = A * a_bar (mod m)
    let d = matrix_vector_mul(&public.a, &a_bar, &shared.ring)?;

    // 3. Calculate d1 = B * (A * (x_bar + a_bar) + a_inner) + a_outer (mod m)
    let x_plus_a = vector_add(&x_bar, &a_bar, &shared.ring)?;
    let a_x_plus_a = matrix_vector_mul(&public.a, &x_plus_a, &shared.ring)?;
    let inner_sum = vector_add(&a_x_plus_a, &public.a_inner, &shared.ring)?;
    let b_inner_sum = matrix_vector_mul(&public.b, &inner_sum, &shared.ring)?;
    let d1 = vector_add(&b_inner_sum, &public.a_outer, &shared.ring)?;

    Ok((d, d1))
}

/// Decrypts a ciphertext block `(d, d1)` using Alice's secret parameters.
///
/// # Arguments
/// * `shared`: Shared parameters.
/// * `secret`: Alice's secret parameters.
/// * `ciphertext`: The ciphertext block `(d, d1)`.
///
/// # Returns
/// The original message block `v` or a `CryptoError`.
pub fn decrypt(
    shared: &SharedParams,
    secret: &AliceSecret,
    d: &Vector,
    d1: &Vector,
) -> Result<Vector, CryptoError> {
    // Check dimensions
    if d.len() != shared.p || d1.len() != shared.p {
        return Err(CryptoError::DimensionMismatch(format!(
            "Ciphertext vectors d and d1 must have length p ({}), got {} and {}",
            shared.p,
            d.len(),
            d1.len()
        )));
    }
    if secret.a_inner.len() != shared.p || secret.a_outer.len() != shared.p {
        return Err(CryptoError::InternalError(
            "Alice's secret vectors have incorrect length".to_string(),
        ));
    }
    if secret.b_inv.len() != shared.p || secret.b_inv[0].len() != shared.p {
        return Err(CryptoError::InternalError(
            "Alice's secret matrix b_inv has incorrect dimensions".to_string(),
        ));
    }

    // 1. Calculate intermediate = B_inv * (d1 - a_outer)
    let d1_minus_outer = vector_sub(d1, &secret.a_outer, &shared.ring)?;
    let b_inv_mult = matrix_vector_mul(&secret.b_inv, &d1_minus_outer, &shared.ring)?;

    // 2. Subtract a_inner: result is v + d
    let v_plus_d = vector_sub(&b_inv_mult, &secret.a_inner, &shared.ring)?;

    // 3. Subtract d to get v
    let v = vector_sub(&v_plus_d, d, &shared.ring)?;

    Ok(v)
}
