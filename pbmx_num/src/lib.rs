#![warn(missing_docs)]
#![feature(iter_unfold)]

//! Numeric utilities for PBMX

#[macro_use]
extern crate serde_derive;

/// Random number generation
pub mod rand;

/// Prime numbers
pub mod prime;

/// Schnorr groups
pub mod schnorr;

/// Fast exponentiation table
pub mod fpowm;
