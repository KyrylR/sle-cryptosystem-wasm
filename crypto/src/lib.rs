#![allow(non_snake_case)] // Allow non-snake_case identifiers (like matrix variable names)

//! # Crypto
//!
//! This library provides the foundational mathematical structures for the SLE cryptosystem.

pub mod codec;
pub mod gen_g;
pub mod keypair;
pub mod ring;
pub mod sle;
pub mod system;

pub use codec::{decrypt_string, encrypt_string};
pub use keypair::{DecryptionSecrets, EncryptionParams, PrivateKey, PublicKey, SharedParams};
pub use ring::*;
pub use system::errors::CryptoError;
