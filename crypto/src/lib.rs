//! # Crypto
//!
//! This library provides the foundational mathematical structures based on the paper
//! "Симетрична криптосистема на основі відображень кілець".

pub mod gen_g;
pub mod ring;
pub mod sle;
pub mod system;
pub mod codec;

pub use ring::*;
pub use system::errors::CryptoError;
pub use system::params::{PublicKey, PrivateKey};
pub use system::setup_shared;
pub use codec::{encrypt_string, decrypt_string};
