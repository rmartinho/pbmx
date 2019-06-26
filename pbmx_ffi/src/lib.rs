#![feature(box_syntax)]
#![feature(try_trait)]
#![feature(raw)]
#![feature(unsize)]
#![allow(missing_docs)]
#![allow(unused_attributes)]
#![deny(clippy::correctness)]

#[macro_use]
mod macros;

pub mod keys;
pub mod random;
pub mod state;

mod buffer;
mod opaque;
mod ptr;
mod result;
mod serde;
