#![allow(clippy::many_single_char_names)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox cryptographic tools

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

mod hash;
pub use hash::{Hash, Xof};
pub mod commit;
pub mod keys;
pub mod map;
pub mod perm;
pub mod proofs;
pub mod vtmf;

mod error;
pub use error::{Error, Result};
