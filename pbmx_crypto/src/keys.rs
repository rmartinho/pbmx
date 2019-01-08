//! ElGamal encryption scheme

use crate::{
    error::Error,
    group::Group,
    hash::Hash,
    num::{fpowm, Coprimes, Modulo},
};
use digest::Digest;
use pbmx_serde::{derive_base64_conversions, ToBytes};
use rand::{distributions::Distribution, thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};
use std::{
    fmt::{self, Debug, Display, Formatter},
    str::{self, FromStr},
};

/// A private key
///
/// This key consists of a secret exponent *x*, together with a Schnorr group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateKey {
    g: Group,
    x: Integer,
}

/// A public key
///
/// This key consists of a public member *h* of a Schnorr group, such that
/// *h* = *g*^*x* mod *p* and *x* is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicKey {
    g: Group,
    h: Integer,
}

/// A public key fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

impl PrivateKey {
    /// Gets this key's group
    pub fn group(&self) -> &Group {
        &self.g
    }

    /// Gets this key's secret value
    pub fn exponent(&self) -> &Integer {
        &self.x
    }

    /// Gets a public key that corresponds with this key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            g: self.g.clone(),
            h: self.g.element(&self.x),
        }
    }

    /// Gets the public key fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// Decrypts a given ciphertext
    pub fn decrypt(&self, c: &(Integer, Integer)) -> Option<Integer> {
        let p = self.g.modulus();
        let c0x = Integer::from(c.0.pow_mod_ref(&self.x, p)?);
        let c0mx = c0x.invert(&p).ok()?;

        Some(&c.1 * c0mx % p)
    }

    /// Signs a given plaintext
    pub fn sign(&self, m: &Integer) -> (Integer, Integer) {
        let p = self.g.modulus();
        let g = self.g.generator();
        let pm1 = p.clone() - 1;

        loop {
            let k = thread_rng().sample(&Coprimes(&pm1));
            let r = fpowm::pow_mod(g, &k, p).unwrap();
            let xr = Integer::from(&self.x * &r);
            let k1 = Integer::from(k.invert_ref(&pm1).unwrap());
            let s = (m - xr) * k1 % &pm1;
            let s = (s + &pm1) % &pm1;
            if s != 0 {
                return (r, s);
            }
        }
    }
}

impl PublicKey {
    /// Gets this key's group
    pub fn group(&self) -> &Group {
        &self.g
    }

    /// Gets this key's public value
    pub fn element(&self) -> &Integer {
        &self.h
    }

    /// Gets this key's fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(self).unwrap()
    }

    /// Combines this public key with another one to form a shared key
    pub fn combine(&mut self, pk: &PublicKey) {
        assert!(pk.g == self.g);
        self.h *= &pk.h;
        self.h %= self.g.modulus();
    }

    /// Encrypts a given plaintext
    pub fn encrypt(&self, m: &Integer) -> (Integer, Integer) {
        let c = (1.into(), m.clone());
        self.reencrypt(&c)
    }

    /// Re-encrypts a given ciphertext
    pub fn reencrypt(&self, c: &(Integer, Integer)) -> (Integer, Integer) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();

        let r = thread_rng().sample(&Modulo(q));
        let gr = fpowm::pow_mod(g, &r, p).unwrap();
        let hr = fpowm::pow_mod(&self.h, &r, p).unwrap();
        let c1 = gr * &c.0 % p;
        let c2 = hr * &c.1 % p;
        (c1, c2)
    }

    /// Verifies a given signature
    pub fn verify(&self, m: &Integer, sig: &(Integer, Integer)) -> bool {
        let p = self.g.modulus();
        let g = self.g.generator();
        let pm1 = p.clone() - 1;
        let (ref r, ref s) = sig;

        if *r < 0 || *r >= *p {
            return false;
        }
        if *s < 0 || *s >= pm1 {
            return false;
        }

        let gm = fpowm::pow_mod(g, m, p).unwrap();
        let hr = fpowm::pow_mod(&self.h, r, p).unwrap();
        let rs = Integer::from(r.pow_mod_ref(s, p).unwrap());

        gm == hr * rs % p
    }
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
        array.copy_from_slice(&hashed);
        Ok(Fingerprint(array))
    }
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PrivateKey {
    unsafe fn new_unchecked(g: Group, x: Integer) -> Self {
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
    unsafe fn new_unchecked(g: Group, h: Integer) -> Self {
        Self { g, h }
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
            .ok_or_else(|| de::Error::custom("invalid key values"))
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
            .ok_or_else(|| de::Error::custom("invalid key values"))
    }
}

#[derive(Deserialize)]
struct KeyRaw {
    g: Group,
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

/// A distribution that produces keys from a Schnorr group.
#[derive(Clone, Debug)]
pub struct Keys<'a>(pub &'a Group);

impl<'a> Distribution<(PrivateKey, PublicKey)> for Keys<'a> {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> (PrivateKey, PublicKey) {
        let x = rng.sample(&Modulo(self.0.order()));

        let sk = PrivateKey {
            g: self.0.clone(),
            x,
        };
        let pk = sk.public_key();

        (sk, pk)
    }
}

const FINGERPRINT_SIZE: usize = 20;

#[cfg(test)]
mod test {
    use super::{Fingerprint, Keys, PrivateKey, PublicKey};
    use crate::group::Groups;
    use rand::{thread_rng, Rng};
    use std::str::FromStr;

    #[test]
    fn keys_produces_valid_keys() {
        let mut rng = thread_rng();
        let dist = Groups {
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
        let dist = Groups {
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
        let dist = Groups {
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
        let dist = Groups {
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
