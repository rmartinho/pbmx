#![warn(missing_docs)]
#![deny(clippy::correctness)]
#![allow(missing_docs)]

//! PBMX toolbox

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

#[macro_use]
pub mod serde;

pub mod chain;
pub mod crypto;

mod error;
pub use self::error::{Error, Result};
