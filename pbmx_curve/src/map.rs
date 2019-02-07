//! Mapping integers to/from the elliptic curve

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Maps an integer to the curve
pub fn to_curve(x: u64) -> RistrettoPoint {
    G * &Scalar::from(x)
}

/// Maps a curve point to an integer
pub fn from_curve(point: &RistrettoPoint) -> Option<u64> {
    CURVE_MAP.get(&point.compress().0).cloned()
}

static CURVE_MAP: phf::Map<[u8; 32], u64> = include!(concat!(env!("OUT_DIR"), "/curve_map.rs"));
