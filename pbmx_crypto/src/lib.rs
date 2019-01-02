#![feature(iter_unfold)]
#![feature(try_from)]
#![allow(clippy::many_single_char_names)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox cryptographic tools

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod macros;

pub mod commit;
pub mod error;
pub mod group;
pub mod hash;
pub mod keys;
pub mod num;
pub mod perm;
pub mod serde;
pub mod vtmf;
pub mod zkp;

/// Result specialization for PBMX errors
pub type Result<T> = std::result::Result<T, self::error::Error>;
