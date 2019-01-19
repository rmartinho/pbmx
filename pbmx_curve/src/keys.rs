//! ElGamal encryption scheme for elliptic curves

#![allow(unused_imports)]

use crate::{error::Error, hash::Hash};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use digest::Digest;
use pbmx_serde::{derive_base64_conversions, ToBytes};
use rand::{distributions::Distribution, thread_rng, CryptoRng, Rng};
use serde::{de, Deserialize, Deserializer};
use std::{
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
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

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
    pub fn point(&self) -> &RistrettoPoint {
        &self.h
    }

    /// Gets this key's fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(self).unwrap()
    }

    /// Combines this public key with another one to form a shared key
    pub fn combine(&mut self, pk: &PublicKey) {
        self.h += &pk.h;
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
        let c1 = c.1 + self.h * r;
        (c0, c1)
    }

    /// Verifies a given signature
    pub fn verify(&self, m: &Scalar, s: &(RistrettoPoint, Scalar)) -> Result<(), ()> {
        let lhs = self.h * point_to_scalar(&s.0) + s.0 * s.1;
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
    pub fn of<T>(x: &T) -> Result<Fingerprint, T::Error>
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
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

derive_base64_conversions!(PrivateKey, Error);
derive_base64_conversions!(PublicKey, Error);

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
            self.0.iter().skip(20 - w)
        } else {
            self.0.iter().skip(0)
        };
        for b in it {
            write!(f, "{:02X}", b)?;
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
            .map_err(pbmx_serde::Error::from)?;
        if bytes.len() != FINGERPRINT_SIZE {
            return Err(pbmx_serde::Error::Hex(None).into());
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
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use rand::thread_rng;
    use std::str::FromStr;

    #[test]
    fn keys_produces_valid_keys() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        assert_eq!(pk.h, G * &sk.x);
    }

    #[test]
    fn private_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let original = PrivateKey::random(&mut rng);

        let exported = original.to_string();
        dbg!(&exported);

        let recovered = PrivateKey::from_str(&exported).unwrap();

        assert_eq!(original.x, recovered.x);
    }

    #[test]
    fn public_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let original = sk.public_key();

        let exported = original.to_string();
        dbg!(&exported);

        let recovered = PublicKey::from_str(&exported).unwrap();

        assert_eq!(original.h, recovered.h);
    }

    #[test]
    fn encryption_roundtrips() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        let original = RistrettoPoint::random(&mut rng);

        let encrypted = pk.encrypt(&original);
        dbg!(&encrypted);

        let recovered = sk.decrypt(&encrypted);

        assert_eq!(original, recovered);
    }

    #[test]
    fn signatures_are_valid() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        let m = Scalar::random(&mut rng);
        dbg!(&m);

        let s = sk.sign(&m);
        dbg!(&s);

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
        dbg!(original);

        let exported = original.to_string();

        let recovered = Fingerprint::from_str(&exported).unwrap();

        assert_eq!(original.0, recovered.0);
    }
}
