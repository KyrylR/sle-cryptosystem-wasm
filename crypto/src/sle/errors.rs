#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SleError {
    #[error("Modulus K must be greater than 1")]
    InvalidModulus,

    #[error("Matrix dimensions are inconsistent: {0}")]
    DimensionMismatch(String),

    #[error("Ring error: {0}")]
    RingError(#[from] crate::ring::RingError),

    #[error("Could not solve system: {0}")]
    SolutionError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("SLE error: {0}")]
    Infinite(String),
}
