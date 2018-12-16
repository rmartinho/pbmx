use crate::{
    crypto::hash::Hash,
    error::Error,
    num::{integer::Modulo, schnorr::SchnorrGroup},
};
use digest::Digest;
use rand::{distributions::Distribution, Rng};
use rug::{integer::Order, Integer};
use serde::{de, Deserialize, Deserializer};
use std::{
    fmt::{self, Display, Formatter},
    str::{self, FromStr},
};

/// A private key
///
/// This key consists of a secret exponent *x*, together with a Schnorr group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateKey {
    pub(super) g: SchnorrGroup,
    pub(super) x: Integer,
}

/// A public key
///
/// This key consists of a public member *h* of a Schnorr group, such that
/// *h* = *g*^*x* mod *p* and *x* is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicKey {
    pub(super) g: SchnorrGroup,
    pub(super) h: Integer,
}

/// A public key fingerprint
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; FINGERPRINT_SIZE]);

impl PrivateKey {
    unsafe fn new_unchecked(g: SchnorrGroup, x: Integer) -> Self {
        Self { g, x }
    }

    fn validate(self) -> Option<Self> {
        if self.x > 1 && self.x < *self.g.order() {
            Some(self)
        } else {
            None
        }
    }
}

impl PublicKey {
    unsafe fn new_unchecked(g: SchnorrGroup, h: Integer) -> Self {
        Self { g, h }
    }

    /// Gets this key's fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        assert!(Hash::output_size() >= FINGERPRINT_SIZE);

        let digest = Hash::new()
            .chain(&self.g.generator().to_digits(Order::MsfBe))
            .chain(&self.g.modulus().to_digits(Order::MsfBe))
            .chain(&self.g.order().to_digits(Order::MsfBe))
            .chain(&self.h.to_digits(Order::MsfBe))
            .result();
        let mut fp = Fingerprint([0; FINGERPRINT_SIZE]);
        fp.0.copy_from_slice(&digest);
        fp
    }

    fn validate(self) -> Option<Self> {
        if self.g.has_element(&self.h) {
            Some(self)
        } else {
            None
        }
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { KeyRaw::deserialize(deserializer)?.into_private() }
            .validate()
            .ok_or(de::Error::custom("invalid key values"))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { KeyRaw::deserialize(deserializer)?.into_public() }
            .validate()
            .ok_or(de::Error::custom("invalid key values"))
    }
}

#[derive(Deserialize)]
struct KeyRaw {
    g: SchnorrGroup,
    i: Integer,
}

impl KeyRaw {
    unsafe fn into_private(self) -> PrivateKey {
        PrivateKey::new_unchecked(self.g, self.i)
    }

    unsafe fn into_public(self) -> PublicKey {
        PublicKey::new_unchecked(self.g, self.i)
    }
}

derive_base64_conversions!(PrivateKey);
derive_base64_conversions!(PublicKey);

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<_> = s
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(str::from_utf8(c).unwrap(), 16))
            .collect::<Result<_, _>>()?;
        if bytes.len() != FINGERPRINT_SIZE {
            return Err(Error::Hex(None));
        }
        let mut fp = Fingerprint([0; FINGERPRINT_SIZE]);
        fp.0.copy_from_slice(&bytes);
        Ok(fp)
    }
}

/// A distribution that produces keys from a Schnorr group.
#[derive(Clone, Debug)]
pub struct Keys<'a>(pub &'a SchnorrGroup);

impl<'a> Distribution<(PrivateKey, PublicKey)> for Keys<'a> {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> (PrivateKey, PublicKey) {
        let x = rng.sample(&Modulo(self.0.order()));

        let h = self.0.element(&x);

        (
            PrivateKey {
                g: self.0.clone(),
                x,
            },
            PublicKey {
                g: self.0.clone(),
                h,
            },
        )
    }
}

const FINGERPRINT_SIZE: usize = 20;

#[cfg(test)]
mod test {
    use super::{Fingerprint, Keys, PrivateKey, PublicKey};
    use crate::num::schnorr::Schnorr;
    use rand::{thread_rng, Rng};
    use std::str::FromStr;

    #[test]
    fn keys_produces_valid_keys() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let dist = Keys(&group);
        let (sk, pk) = rng.sample(&dist);

        assert_eq!(sk.g, group);
        assert!(
            sk.x < *group.order(),
            "x is not modulo the group order\n\tx = {}\n\torder = {}",
            sk.x,
            group.order()
        );

        assert_eq!(pk.g, group);
        assert!(
            group.has_element(&pk.h),
            "public key is not an element of the group\n\tgenerator = {}\n\tmodulus = {}\n\th = {}",
            group.generator(),
            group.modulus(),
            pk.h
        );
        assert_eq!(pk.h, group.element(&sk.x));
    }

    #[test]
    fn public_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let dist = Keys(&group);
        let (_, original) = rng.sample(&dist);
        println!("key = {}", original);

        let exported = original.to_string();

        let recovered = PublicKey::from_str(&exported).unwrap();

        assert_eq!(original.g, recovered.g);
        assert_eq!(original.h, recovered.h);
    }

    #[test]
    fn private_key_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let dist = Keys(&group);
        let (original, _) = rng.sample(&dist);
        println!("key = {}", original);

        let exported = original.to_string();

        let recovered = PrivateKey::from_str(&exported).unwrap();

        assert_eq!(original.g, recovered.g);
        assert_eq!(original.x, recovered.x);
    }

    #[test]
    fn fingerprint_roundtrips_via_string() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let dist = Keys(&group);
        let (_, pk) = rng.sample(&dist);
        let original = pk.fingerprint();
        println!("fingerprint = {}", original);

        let exported = original.to_string();

        let recovered = Fingerprint::from_str(&exported).unwrap();

        assert_eq!(original.0, recovered.0);
    }
}
