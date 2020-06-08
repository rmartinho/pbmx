//! ElGamal encryption scheme for elliptic curves

use crate::{proto, random::thread_rng, serde::ToBytes, Error};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use digest::{generic_array::typenum::U32, Digest};
use merlin::Transcript;
use rand::{CryptoRng, Rng};
use schnorrkel::{self, Signature, context::attach_rng};
use std::{
    borrow::Borrow,
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
    ops::Deref,
    str::{self, FromStr},
};

/// A private key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey(schnorrkel::SecretKey);

/// A public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    h: RistrettoPoint,
}

/// A public key fingerprint
#[repr(C)]
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

create_hash! {
    /// The hash used for key fingerprints
    pub struct FingerprintHash(Hash<U32>) = b"pbmx-key-fp";
}

impl Deref for Fingerprint {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for Fingerprint {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

impl PrivateKey {
    /// Gets this key's secret value
    pub fn exponent(&self) -> Scalar {
        let bytes = self.0.to_bytes();
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);
        Scalar::from_bits(array)
    }

    /// Generates a random Ristretto secret key
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self(schnorrkel::SecretKey::generate_with(rng))
    }

    /// Gets a public key that corresponds with this key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            h: self.0.to_public().into_point(),
        }
    }

    /// Gets the public key fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// Decrypts a given ciphertext
    pub fn decrypt(&self, c: &(RistrettoPoint, RistrettoPoint)) -> RistrettoPoint {
        c.1 - c.0 * self.exponent()
    }

    /// Signs a given transcript under a given context
    pub fn sign(&self, t: &mut Transcript) -> Signature {
        let pk = self.0.to_public();
        self.0.sign(attach_rng(t, &mut thread_rng()), &pk)
    }
}

impl PublicKey {
    /// Gets this key's public value
    pub fn point(&self) -> RistrettoPoint {
        self.h
    }

    /// Gets this key's fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        let bytes = self.h.to_bytes().unwrap();
        let hashed = FingerprintHash::new().chain(bytes).result();
        let mut array = [0u8; FINGERPRINT_SIZE];
        array.copy_from_slice(&hashed[..FINGERPRINT_SIZE]);
        Fingerprint(array)
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

    /// Verifies a given transcript signature
    pub fn verify(&self, t: &mut Transcript, s: &Signature) -> Result<(), ()> {
        let pk = schnorrkel::PublicKey::from_point(self.h.clone());
        pk.verify(t, s).map_err(|_| ())
    }
}

impl Fingerprint {
    /// Gets the fingerprint of some object
    pub fn of<D>(x: &(dyn ToBytes)) -> Result<Fingerprint, Error>
    where
        D: Digest + Default,
    {
        debug_assert!(D::output_size() == FINGERPRINT_SIZE);
        let bytes = x.to_bytes()?;
        let hashed = D::default().chain(bytes).result();
        let mut array = [0u8; FINGERPRINT_SIZE];
        array.copy_from_slice(&hashed[..]);
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

derive_opaque_proto_conversions!(PrivateKey: proto::PrivateKey);
derive_opaque_proto_conversions!(PublicKey: proto::PublicKey);

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
        (self as &dyn Display).fmt(f)
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

impl<'a> TryFrom<&'a Vec<u8>> for Fingerprint {
    type Error = Error;

    fn try_from(v: &'a Vec<u8>) -> Result<Fingerprint, Error> {
        if v.len() != FINGERPRINT_SIZE {
            return Err(Error::Decoding);
        }
        let mut array = [0u8; FINGERPRINT_SIZE];
        array.copy_from_slice(&v[..]);
        Ok(Fingerprint(array))
    }
}

const FINGERPRINT_SIZE: usize = 32;

#[cfg(test)]
mod tests {
    use super::{Fingerprint, PrivateKey, PublicKey, G};
    use crate::serde::{FromBase64, ToBase64};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use rand::thread_rng;
    use schnorrkel::signing_context;
    use std::str::FromStr;

    #[test]
    fn keys_produces_valid_keys() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();

        assert_eq!(pk.point(), G * &sk.exponent());
    }

    #[test]
    fn private_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let original = PrivateKey::random(&mut rng);

        let exported = original.to_base64().unwrap();

        let recovered = PrivateKey::from_base64(&exported).unwrap();

        assert_eq!(original.exponent(), recovered.exponent());
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
        let mut t = signing_context(b"test").bytes(&m.to_bytes());
        let s = sk.sign(&mut t);

        let mut t = signing_context(b"test").bytes(&m.to_bytes());
        let r = pk.verify(&mut t, &s);

        assert_eq!(r, Ok(()));

        let m = m + Scalar::one();
        let mut t = signing_context(b"test").bytes(&m.to_bytes());
        let r = pk.verify(&mut t, &s);

        assert_eq!(r, Err(()));
    }

    #[test]
    fn fingerprint_roundtrips_via_string() {
        let original = Fingerprint::random(&mut thread_rng());

        let exported = original.to_string();

        let recovered = Fingerprint::from_str(&exported).unwrap();

        assert_eq!(original.0, recovered.0);
    }
}
