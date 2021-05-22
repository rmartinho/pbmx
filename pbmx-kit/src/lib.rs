#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox

#[macro_use]
extern crate pest;
#[macro_use]
extern crate pest_derive;

#[macro_use]
pub mod serde;

pub mod chain;
pub mod crypto;
pub mod proto;
pub mod random;
pub mod state;

mod error;
pub use self::error::{Error, Result};
