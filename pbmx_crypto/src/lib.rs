#![feature(iter_unfold)]
#![feature(try_from)]
#![feature(proc_macro_hygiene)]
#![allow(clippy::many_single_char_names)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox cryptographic tools

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

pub mod commit;
pub mod hash;
pub mod keys;
pub mod num;
pub mod perm;
pub mod schnorr;
pub mod vtmf;
pub mod zkp;

mod error;
pub use self::error::{Error, Result};
