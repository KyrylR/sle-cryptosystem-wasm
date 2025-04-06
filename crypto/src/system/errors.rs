use crate::gen_g::GenGError;
use crate::ring::RingError;
use crate::sle::SleError;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Ring operation error: {0}")]
    Ring(#[from] RingError),

    #[error("SLE solver error: {0}")]
    Sle(#[from] SleError),

    #[error("GenG algorithm error: {0}")]
    GenG(#[from] GenGError), // If needed later

    #[error("Setup failed: {0}")]
    SetupFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encoding failed: {0}")]
    EncodingError(String),

    #[error("Decoding failed: {0}")]
    DecodingError(String),

    #[error("Serialization failed: {0}")]
    SerializationError(String),

    #[error("Deserialization failed: {0}")]
    DeserializationError(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Dimension mismatch: {0}")]
    DimensionMismatch(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}
