#![feature(option_xor)]
#![feature(box_syntax)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox

#[macro_use]
extern crate nom;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

#[macro_use]
pub mod serde;

pub mod chain;
pub mod crypto;
pub mod state;

mod error;
pub use self::error::{Error, Result};
