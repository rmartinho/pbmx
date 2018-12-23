//! Numeric utilities

mod integer;
pub use self::integer::*;

mod prime;
pub use self::prime::*;

/// Fast exponentiation table
pub(crate) mod fpowm;
