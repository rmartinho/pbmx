//! ElGamal encryption scheme for elliptic curves

use crate::{crypto::hash::Hash, serde::ToBytes, Error};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use digest::Digest;
use rand::{thread_rng, CryptoRng, Rng};
use std::{
    borrow::Borrow,
    fmt::{self, Debug, Display, Formatter},
    str::{self, FromStr},
};

/// A private key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey {
    x: Scalar,
}

/// A public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    h: RistrettoPoint,
}

/// A public key fingerprint
#[repr(C)]
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

impl Borrow<[u8]> for Fingerprint {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

impl PrivateKey {
    /// Gets this key's secret value
    pub fn exponent(&self) -> &Scalar {
        &self.x
    }

    /// Generates a random Ristretto secret key
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let x = Scalar::random(rng);
        Self { x }
    }

    /// Gets a public key that corresponds with this key
    pub fn public_key(&self) -> PublicKey {
        PublicKey { h: G * &self.x }
    }

    /// Gets the public key fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// Decrypts a given ciphertext
    pub fn decrypt(&self, c: &(RistrettoPoint, RistrettoPoint)) -> RistrettoPoint {
        c.1 - c.0 * self.x
    }

    /// Signs a given messages
    pub fn sign(&self, m: &Scalar) -> (RistrettoPoint, Scalar) {
        let mut rng = thread_rng();
        let zero = Scalar::zero();
        loop {
            let k = Scalar::random(&mut rng);
            let s0 = G * &k;
            let s1 = k.invert() * (m - self.x * point_to_scalar(&s0));
            if s1 != zero {
                return (s0, s1);
            }
        }
    }
}

impl PublicKey {
    /// Gets this key's public value
    pub fn point(&self) -> RistrettoPoint {
        self.h
    }

    /// Gets this key's fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(self).unwrap()
    }

    /// Combines this public key with another one to form a shared key
    pub fn combine(&mut self, pk: &PublicKey) {
        self.h += pk.h
    }

    /// Encrypts a given plaintext
    pub fn encrypt(&self, m: &RistrettoPoint) -> (RistrettoPoint, RistrettoPoint) {
        self.reencrypt(&(RistrettoPoint::identity(), *m))
    }

    /// Re-encrypts a given ciphertext
    pub fn reencrypt(
        &self,
        c: &(RistrettoPoint, RistrettoPoint),
    ) -> (RistrettoPoint, RistrettoPoint) {
        let mut rng = thread_rng();
        let r = Scalar::random(&mut rng);
        let c0 = c.0 + G * &r;
        let c1 = c.1 + self.point() * r;
        (c0, c1)
    }

    /// Verifies a given signature
    pub fn verify(&self, m: &Scalar, s: &(RistrettoPoint, Scalar)) -> Result<(), ()> {
        let lhs = self.point() * point_to_scalar(&s.0) + s.0 * s.1;
        let rhs = G * m;
        if lhs == rhs {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn point_to_scalar(x: &RistrettoPoint) -> Scalar {
    Scalar::from_bytes_mod_order(x.compress().to_bytes())
}

impl Fingerprint {
    /// Gets the fingerprint of some object
    pub fn of<T>(x: &T) -> Result<Fingerprint, Error>
    where
        T: ToBytes,
    {
        debug_assert!(Hash::output_size() >= FINGERPRINT_SIZE);
        let bytes = x.to_bytes()?;
        let hashed = Hash::new().chain(bytes).result();
        let mut array = [0u8; FINGERPRINT_SIZE];
        array.copy_from_slice(&hashed[..FINGERPRINT_SIZE]);
        Ok(Fingerprint(array))
    }

    /// Generates a random fingerprint
    pub fn random<R: Rng>(r: &mut R) -> Fingerprint {
        let mut array = [0u8; FINGERPRINT_SIZE];
        r.fill(&mut array);
        Fingerprint(array)
    }
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

derive_base64_conversions!(PrivateKey);
derive_base64_conversions!(PublicKey);

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let it = if let Some(mut w) = f.width() {
            if w % 2 == 1 {
                w += 1;
            }
            if w >= 40 {
                w = 40;
            }
            w /= 2;
            self.0.iter().take(w)
        } else {
            self.0.iter().take(self.0.len())
        };
        for b in it {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
impl Debug for Fingerprint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        (self as &Display).fmt(f)
    }
}
impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<_> = s
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(str::from_utf8(c).unwrap(), 16))
            .collect::<Result<_, _>>()
            .map_err(|_| Error::Decoding)?;

        if bytes.len() != FINGERPRINT_SIZE {
            return Err(Error::Decoding);
        }

        let mut fp = Fingerprint([0; FINGERPRINT_SIZE]);
        fp.0.copy_from_slice(&bytes);
        Ok(fp)
    }
}

const FINGERPRINT_SIZE: usize = 20;

#[cfg(test)]
mod tests {
    use super::{Fingerprint, PrivateKey, PublicKey, G};
    use crate::serde::{FromBase64, ToBase64};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use rand::thread_rng;
    use std::str::FromStr;

    #[test]
    fn keys_produces_valid_keys() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        assert_eq!(pk.point(), G * &sk.x);
    }

    #[test]
    fn private_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let original = PrivateKey::random(&mut rng);

        let exported = original.to_base64().unwrap();

        let recovered = PrivateKey::from_base64(&exported).unwrap();

        assert_eq!(original.x, recovered.x);
    }

    #[test]
    fn public_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let original = sk.public_key();

        let exported = original.to_base64().unwrap();

        let recovered = PublicKey::from_base64(&exported).unwrap();

        assert_eq!(original.h, recovered.h);
    }

    #[test]
    fn encryption_roundtrips() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        let original = RistrettoPoint::random(&mut rng);

        let encrypted = pk.encrypt(&original);

        let recovered = sk.decrypt(&encrypted);

        assert_eq!(original, recovered);
    }

    #[test]
    fn signatures_are_valid() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        let m = Scalar::random(&mut rng);

        let s = sk.sign(&m);

        let r = pk.verify(&m, &s);

        assert_eq!(r, Ok(()));

        let m = m + Scalar::one();
        let r = pk.verify(&m, &s);

        assert_eq!(r, Err(()));
    }

    #[test]
    fn fingerprint_roundtrips_via_string() {
        let v = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let original = Fingerprint::of(&v).unwrap();

        let exported = original.to_string();

        let recovered = Fingerprint::from_str(&exported).unwrap();

        assert_eq!(original.0, recovered.0);
    }
}
