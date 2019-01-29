#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox blockchain tools

#[macro_use]
extern crate serde_derive;

pub mod block;
pub mod chain;
pub mod payload;

mod error;
pub use self::error::{Error, Result};

pub use pbmx_curve::keys::Fingerprint as Id;
