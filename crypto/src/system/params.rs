use crate::ring::Ring;
use crate::system::matrix_ops::{Matrix, Vector};

/// Parameters shared between Alice and Bob.
#[derive(Debug, Clone)]
pub struct SharedParams {
    pub m: u64,     // Modulus for Z_m
    pub ring: Ring, // Ring instance for Z_m operations
    pub p: usize,   // Number of equations / message block size
    pub q: usize,   // Number of variables (q > p usually)
}

/// Parameters known only to Alice (for decryption).
#[derive(Debug, Clone)]
pub struct AliceSecret {
    pub b_inv: Matrix,   // Inverse of matrix B (p x p)
    pub a_inner: Vector, // Inner constant vector (p x 1)
    pub a_outer: Vector, // Outer constant vector (p x 1)
}

/// Parameters known to Bob (published by Alice for encryption).
#[derive(Debug, Clone)]
pub struct BobPublic {
    pub a: Matrix,       // Matrix A (p x q)
    pub b: Matrix,       // Matrix B (p x p)
    pub a_inner: Vector, // Inner constant vector (p x 1)
    pub a_outer: Vector, // Outer constant vector (p x 1)
}

// --- High-Level Key Structures ---

/// Public key data needed for encryption.
#[derive(Debug, Clone)]
pub struct PublicKey {
    pub shared: SharedParams,
    pub bob_public: BobPublic, // Contains matrices A, B and vectors a_inner, a_outer
}

/// Private key data needed for decryption.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub shared: SharedParams,
    pub alice_secret: AliceSecret, // Contains matrix b_inv and vectors a_inner, a_outer
}
