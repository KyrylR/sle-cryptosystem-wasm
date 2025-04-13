#![allow(non_snake_case)] // Allow non-snake_case identifiers (like matrix variable names)

//! # Ring Crypto Module
//!
//! Provides the [`Ring`] struct for representing finite rings Z_k and performing modular arithmetic.

pub mod helper;
pub mod math;
pub mod matrix_ops;

/// Represents a mathematical vector using a `Vec<i64>`.
pub type Vector = Vec<i64>;
/// Represents a mathematical matrix using a `Vec<Vec<i64>>`.
pub type Matrix = Vec<Vec<i64>>;

pub use helper::{extended_gcd, gcd};
pub use math::Ring;
