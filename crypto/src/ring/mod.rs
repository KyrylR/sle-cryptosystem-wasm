#![allow(non_snake_case)] // Allow non-snake_case identifiers (like matrix variable names)

//! # Ring Crypto Module
//!
//! Provides the [`Ring`] struct for representing finite rings Z_k and performing modular arithmetic.

pub mod errors;
pub mod helper;
pub mod math;

pub use errors::RingError;
pub use helper::{extended_gcd, gcd}; // Expose gcd as well
pub use math::Ring;
