use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// A masked value
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mask(pub RistrettoPoint, pub RistrettoPoint);

derive_base64_conversions!(Mask);

impl Mask {
    /// Creates a new open masking
    pub fn open(p: RistrettoPoint) -> Mask {
        Mask(RistrettoPoint::identity(), p)
    }
}

impl Identity for Mask {
    fn identity() -> Self {
        Mask(RistrettoPoint::identity(), RistrettoPoint::identity())
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Mask {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.compress().as_bytes().hash(state);
        self.1.compress().as_bytes().hash(state);
    }
}

impl From<(RistrettoPoint, RistrettoPoint)> for Mask {
    fn from(pair: (RistrettoPoint, RistrettoPoint)) -> Mask {
        Mask(pair.0, pair.1)
    }
}

impl<'a, 'b> Add<&'b Mask> for &'a Mask {
    type Output = Mask;

    fn add(self, rhs: &'b Mask) -> Mask {
        Mask(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<'b> Add<&'b Mask> for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: &'b Mask) -> Mask {
        &self + rhs
    }
}

impl<'a> Add<Mask> for &'a Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Mask) -> Mask {
        self + &rhs
    }
}

impl Add<Mask> for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Mask) -> Mask {
        &self + &rhs
    }
}

impl<'b> AddAssign<&'b Mask> for Mask {
    fn add_assign(&mut self, rhs: &'b Mask) {
        self.0 += rhs.0;
        self.1 += rhs.1;
    }
}

impl AddAssign<Mask> for Mask {
    #[allow(clippy::op_ref)]
    fn add_assign(&mut self, rhs: Mask) {
        *self += &rhs;
    }
}

impl<'a, 'b> Sub<&'b Mask> for &'a Mask {
    type Output = Mask;

    fn sub(self, rhs: &'b Mask) -> Mask {
        Mask(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<'b> Sub<&'b Mask> for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: &'b Mask) -> Mask {
        &self - rhs
    }
}

impl<'a> Sub<Mask> for &'a Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Mask) -> Mask {
        self - &rhs
    }
}

impl Sub<Mask> for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Mask) -> Mask {
        &self - &rhs
    }
}

impl<'b> SubAssign<&'b Mask> for Mask {
    fn sub_assign(&mut self, rhs: &'b Mask) {
        self.0 -= rhs.0;
        self.1 -= rhs.1;
    }
}

impl SubAssign<Mask> for Mask {
    #[allow(clippy::op_ref)]
    fn sub_assign(&mut self, rhs: Mask) {
        *self -= &rhs;
    }
}

impl<T> Sum<T> for Mask
where
    T: Borrow<Mask>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Mask::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a Mask {
    type Output = Mask;

    fn neg(self) -> Mask {
        Mask(-self.0, -self.1)
    }
}

impl Neg for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn neg(self) -> Mask {
        -&self
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Mask {
    type Output = Mask;

    fn mul(self, rhs: &'b Scalar) -> Mask {
        Mask(self.0 * rhs, self.1 * rhs)
    }
}

impl<'a, 'b> Mul<&'b Mask> for &'a Scalar {
    type Output = Mask;

    fn mul(self, rhs: &'b Mask) -> Mask {
        Mask(self * rhs.0, self * rhs.1)
    }
}

impl<'b> Mul<&'b Scalar> for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &'b Scalar) -> Mask {
        &self * rhs
    }
}

impl<'b> Mul<&'b Mask> for Scalar {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &'b Mask) -> Mask {
        &self * rhs
    }
}

impl<'a> Mul<Scalar> for &'a Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Scalar) -> Mask {
        self * &rhs
    }
}

impl<'a> Mul<Mask> for &'a Scalar {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Mask) -> Mask {
        self * &rhs
    }
}

impl Mul<Scalar> for Mask {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Scalar) -> Mask {
        &self * &rhs
    }
}

impl Mul<Mask> for Scalar {
    type Output = Mask;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Mask) -> Mask {
        &self * &rhs
    }
}

impl<'b> MulAssign<&'b Scalar> for Mask {
    fn mul_assign(&mut self, rhs: &'b Scalar) {
        self.0 *= rhs;
        self.1 *= rhs;
    }
}

impl MulAssign<Scalar> for Mask {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self *= &rhs;
    }
}
