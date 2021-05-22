//! Mapping integers to/from the elliptic curve

use crate::random::thread_rng;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use rand::Rng;

const START_BYTE: usize = 12;
const END_BYTE: usize = START_BYTE + 8;

/// Maps an integer to the curve
///
/// Each 8-byte integer is mapped into a point whose compressed encoding has bytes [12..20] equal
/// to the integer's bytes in little-endian order, and the other 24 bytes are random. This means
/// each integer can be mapped into many different points.
pub fn to_curve(x: u64) -> RistrettoPoint {
    let mut rng = thread_rng();
    let mut buf = [0u8; 32];
    buf[START_BYTE..END_BYTE].copy_from_slice(&x.to_le_bytes());
    loop {
        rng.fill(&mut buf[..START_BYTE]);
        rng.fill(&mut buf[END_BYTE..]);
        if let Some(p) = CompressedRistretto::from_slice(&buf).decompress() {
            break p;
        }
    }
}

/// Maps a curve point to an integer
///
/// Each curve point is mapped into an 8-byte integer whose bytes in little-endian order are bytes
/// [12..20] of the point's compressed encoding. This means that many different points can be
/// mapped into the same integer.
pub fn from_curve(point: &RistrettoPoint) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&point.compress().0[START_BYTE..END_BYTE]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod test {
    use super::{from_curve, to_curve};

    #[test]
    fn curve_mapping_is_invertible() {
        for i in 0..32 {
            let p = to_curve(i);
            assert_eq!(from_curve(&p), i);
        }
        for i in (std::u64::MAX - 32)..std::u64::MAX {
            let p = to_curve(i);
            assert_eq!(from_curve(&p), i);
        }
    }
}
