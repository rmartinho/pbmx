#![allow(dead_code)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};

/// A masked value
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mask(pub RistrettoPoint, pub RistrettoPoint);

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

impl Mask {
    /// Creates a new open masking
    pub fn open(m: &Scalar) -> Mask {
        Mask(RistrettoPoint::identity(), G * m)
    }
}
