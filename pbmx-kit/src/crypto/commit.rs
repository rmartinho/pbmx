//! Pedersen commitment scheme

use crate::{Error, Result};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use rand::{CryptoRng, Rng};
use std::iter;

/// The Pedersen commitment scheme
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedersen {
    h: RistrettoPoint,
    g: Vec<RistrettoPoint>,
}

impl Pedersen {
    unsafe fn new_unchecked(h: RistrettoPoint, g: Vec<RistrettoPoint>) -> Self {
        Self { h, g }
    }

    /// Creates a new commitment scheme with given generators
    pub fn new(h: RistrettoPoint, g: Vec<RistrettoPoint>) -> Option<Self> {
        // SAFE: the value is checked before returning
        unsafe { Self::new_unchecked(h, g) }.validate()
    }

    /// Creates a new commitment scheme with random generators
    pub fn random<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Self {
        loop {
            let h = RistrettoPoint::random(rng);
            let g = iter::repeat_with(|| RistrettoPoint::random(rng))
                .take(n)
                .collect();
            // SAFE: the value is checked before returning
            let scheme = unsafe { Self::new_unchecked(h, g) }.validate();
            if let Some(scheme) = scheme {
                return scheme;
            }
        }
    }

    /// Gets the public point (aka *h*) for this commitment scheme
    pub fn shared_point(&self) -> &RistrettoPoint {
        &self.h
    }

    /// Gets the points (aka *g*) for this commitment scheme
    pub fn points(&self) -> &[RistrettoPoint] {
        &self.g
    }

    /// Creates a commitment to a given sequence of scalars
    pub fn commit_to<R: Rng + CryptoRng>(
        &self,
        m: &[Scalar],
        rng: &mut R,
    ) -> (RistrettoPoint, Scalar) {
        assert!(m.len() == self.g.len());

        let r = Scalar::random(rng);
        let c = self.commit_by(m, &r);
        (c, r)
    }

    /// Creates a commitment to a given sequence of scalars by a given
    /// randomizer.
    pub fn commit_by(&self, m: &[Scalar], r: &Scalar) -> RistrettoPoint {
        assert!(m.len() == self.g.len());

        let gm = RistrettoPoint::multiscalar_mul(m.iter(), self.g.iter());

        gm + self.h * r
    }

    /// Verifies a commitment to a given sequence of scalars
    pub fn open(&self, c: &RistrettoPoint, m: &[Scalar], r: &Scalar) -> Result<()> {
        assert!(m.len() == self.g.len());

        let c1 = self.commit_by(m, r);
        if *c == c1 {
            Ok(())
        } else {
            Err(Error::BadProof)
        }
    }

    fn validate(self) -> Option<Self> {
        for i in 0..self.g.len() {
            for j in 0..i {
                if self.g[i] == self.g[j] {
                    return None;
                }
            }
        }

        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::Pedersen;
    use crate::Error;
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

    #[test]
    fn pedersen_scheme_commitments_agree_with_validation() {
        let mut rng = thread_rng();
        let com = Pedersen::random(3, &mut rng);
        let m = [
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];
        let (c, r) = com.commit_to(&m, &mut rng);
        let open = com.open(&c, &m, &r);
        assert_eq!(open, Ok(()));
        let fake = [m[1], m[2], Scalar::random(&mut rng)];
        let (c1, r1) = com.commit_to(&fake, &mut rng);
        let open = com.open(&c1, &m, &r1);
        assert_eq!(open, Err(Error::BadProof));
    }
}
