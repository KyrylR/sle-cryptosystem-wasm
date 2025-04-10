pub mod errors;
pub mod matrix_ops;

use crate::keypair::{PrivateKey, PublicKey};
use crate::sle::{Solution, solve as solve_sle};

use errors::CryptoError;

use matrix_ops::{Vector, matrix_vector_mul, vector_add, vector_sub};

use rand::{Rng, SeedableRng, rngs::StdRng};

/// Encrypts a message block `v` using the public key.
///
/// # Arguments
/// * `public_key`: The public key.
/// * `v`: The message block (vector of length `p`).
/// * `seed`: Seed to generate the random vector `a_bar`. Using a seed makes
///           encryption deterministic for testing/debugging, use a real RNG in practice.
///
/// # Returns
/// The ciphertext block `(d, d1)` or a `CryptoError`.
pub fn encrypt(
    public_key: &PublicKey,
    v: &Vector,
    seed: u64,
) -> Result<(Vector, Vector), CryptoError> {
    let shared = &public_key.shared;
    let public = &public_key.encryption_params;

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
    // Note: Paper uses l(x) = Ax, L(x) = B * (l(x) + a_inner) + a_outer (slightly simplified here)
    // The implementation follows: L(x + a_bar) = B * (A * (x_bar + a_bar) + a_inner) + a_outer
    let x_plus_a = vector_add(&x_bar, &a_bar, &shared.ring)?;
    let a_x_plus_a = matrix_vector_mul(&public.a, &x_plus_a, &shared.ring)?;
    let inner_sum = vector_add(&a_x_plus_a, &public.a_inner, &shared.ring)?;
    let b_inner_sum = matrix_vector_mul(&public.b, &inner_sum, &shared.ring)?;
    let d1 = vector_add(&b_inner_sum, &public.a_outer, &shared.ring)?;

    Ok((d, d1))
}

/// Decrypts a ciphertext block `(d, d1)` using the private key.
///
/// # Arguments
/// * `private_key`: The private key.
/// * `ciphertext`: The ciphertext block `(d, d1)`.
///
/// # Returns
/// The original message block `v` or a `CryptoError`.
pub fn decrypt(private_key: &PrivateKey, d: &Vector, d1: &Vector) -> Result<Vector, CryptoError> {
    let shared = &private_key.public_key.shared;
    let secret = &private_key.decryption_secrets;

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

    // Decryption steps based on the proof in the paper:
    // d1 = B * (A * (x_bar + a_bar) + a_inner) + a_outer
    // B_inv * (d1 - a_outer) = A * (x_bar + a_bar) + a_inner
    // B_inv * (d1 - a_outer) - a_inner = A * (x_bar + a_bar)
    // We know d = A * a_bar
    // The value we want is v = A * x_bar
    // So, A * (x_bar + a_bar) - d = A * x_bar = v

    // 1. Calculate intermediate = B_inv * (d1 - a_outer)
    let d1_minus_outer = vector_sub(d1, &secret.a_outer, &shared.ring)?;
    let b_inv_mult = matrix_vector_mul(&secret.b_inv, &d1_minus_outer, &shared.ring)?;

    // 2. Subtract a_inner: result is A * (x_bar + a_bar)
    let a_x_plus_a_bar = vector_sub(&b_inv_mult, &secret.a_inner, &shared.ring)?;

    // 3. Subtract d: result is A * x_bar = v
    let v = vector_sub(&a_x_plus_a_bar, d, &shared.ring)?;

    Ok(v)
}
