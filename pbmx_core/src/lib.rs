#![warn(missing_docs)]
#![feature(iter_unfold)]

//! PBMX toolbox crate

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod macros;

pub mod crypto;
pub mod error;
pub mod num;
pub mod perm;
