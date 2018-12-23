#![feature(iter_unfold)]
#![feature(try_from)]
#![allow(clippy::many_single_char_names)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox crate

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod macros;

pub mod barnett_smart;
pub mod elgamal;
pub mod error;
pub mod hash;
pub mod num;
pub mod pedersen;
pub mod perm;
pub mod schnorr;

/// Result specialization for PBMX errors
pub type Result<T> = std::result::Result<T, self::error::Error>;
