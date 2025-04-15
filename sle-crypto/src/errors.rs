#[derive(thiserror::Error, Debug)]
pub enum SLECryptoError {
    /// Error when trying to find a modular inverse that doesn't exist (gcd(a, k) != 1).
    #[error("NoInverse: {0}")]
    NoInverse(String),
    /// Error when creating a ring with an invalid modulus (k <= 1).
    #[error("InvalidModulus: {0}")]
    InvalidModulus(String),
    #[error("DimensionMismatch: {0}")]
    DimensionMismatch(String),
    #[error("InternalError: {0}")]
    InternalError(String),

    #[error("Input order k must be positive")]
    KMustBePositive,
    #[error("Input parameter l must be positive and divide k")]
    InvalidLValue,
    #[error("GCD(a, k) must be 1, but the calculated GCD was {0}")]
    GcdAKConstraintNotMet(i64),
    #[error("Internal error: Value 0 not found in sequence b")]
    ValueZeroNotFound,
    #[error("Internal error: Value 1 not found in sequence b")]
    ValueOneNotFound,

    #[error("InvalidParameters: {0}")]
    InvalidParameters(String),

    #[error("Data serialization: {0}")]
    SerializationError(#[from] serde_json::Error),
}
