//! Mapping integers to/from the elliptic curve

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use rand::{thread_rng, Rng};

const START_BIT: usize = 12;
const END_BIT: usize = START_BIT + 8;

/// Maps an integer to the curve
pub fn to_curve(x: u64) -> RistrettoPoint {
    let mut rng = thread_rng();
    let mut buf = [0u8; 32];
    buf[START_BIT..END_BIT].copy_from_slice(&x.to_le_bytes());
    loop {
        rng.fill(&mut buf[..START_BIT]);
        rng.fill(&mut buf[END_BIT..]);
        if let Some(p) = CompressedRistretto::from_slice(&buf).decompress() {
            break p;
        }
    }
}

/// Maps a curve point to an integer
pub fn from_curve(point: &RistrettoPoint) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&point.compress().0[START_BIT..END_BIT]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod test {
    use super::{from_curve, to_curve};

    #[test]
    fn curve_mapping_is_injective() {
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
