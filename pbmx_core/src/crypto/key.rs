use crate::num::{integer::Modulo, schnorr::SchnorrGroup};
use rand::{distributions::Distribution, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};

/// A private key
///
/// This key consists of a secret exponent *x*, together with a Schnorr group.
#[derive(Clone, Debug, Serialize)]
pub struct PrivateKey {
    pub(crate) g: SchnorrGroup,
    pub(crate) x: Integer,
}

/// A public key
///
/// This key consists of a public member *h* of a Schnorr group, such that
/// *h* = *g*^*x* mod *p* and *x* is secret.
#[derive(Clone, Debug, Serialize)]
pub struct PublicKey {
    pub(crate) g: SchnorrGroup,
    pub(crate) h: Integer,
}

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

#[cfg(test)]
mod test {
    use super::Keys;
    use crate::num::schnorr::Schnorr;
    use rand::{thread_rng, Rng};

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
        assert!(sk.x < *group.order());

        assert_eq!(pk.g, group);
        assert!(group.has_element(&pk.h));
        assert_eq!(pk.h, group.element(&sk.x));
    }
}
