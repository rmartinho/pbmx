#![feature(box_syntax)]
#![feature(vec_remove_item)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox

#[macro_use]
extern crate nom;

#[macro_use]
mod macros;

#[macro_use]
pub mod serde;

pub mod chain;
pub mod crypto;
pub mod proto;
pub mod random;
pub mod state;

mod error;
pub use self::error::{Error, Result};
