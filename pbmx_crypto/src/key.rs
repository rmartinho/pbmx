use pbmx_num::{fpowm::FastPowModTable, rand::Modulo, schnorr::SchnorrGroup};
use rand::{distributions::Distribution, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};

/// A private key
///
/// This key consists of a secret exponent *x*, together with a Schnorr group.
#[derive(Clone, Debug, Serialize)]
pub struct PrivateKey {
    g: SchnorrGroup,
    x: Integer,
}

/// A public key
///
/// This key consists of a public member *h* of a Schnorr group, such that
/// *h* = *g*^*x* mod *p* and *x* is secret.
#[derive(Clone, Debug, Serialize)]
pub struct PublicKey {
    g: SchnorrGroup,
    h: Integer,
}

/// A shared key
///
/// This is a key constructed by combining several public keys. No one holds the
/// complete secret key.
#[derive(Clone, Debug, Serialize)]
pub struct SharedKey {
    g: SchnorrGroup,
    h: Integer,

    #[serde(skip)]
    fpowm: FastPowModTable,
}

impl PrivateKey {
    unsafe fn new_unchecked(g: SchnorrGroup, x: Integer) -> Self {
        Self { g, x }
    }

    /// Gets the group used by this key
    pub fn group(&self) -> &SchnorrGroup {
        &self.g
    }

    /// Gets this key's secret value
    pub fn value(&self) -> &Integer {
        &self.x
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

impl SharedKey {
    unsafe fn new_unchecked(g: SchnorrGroup, h: Integer) -> Self {
        Self {
            fpowm: FastPowModTable::new(g.order().significant_bits(), g.modulus(), &h),
            g,
            h,
        }
    }

    /// Gets the group used by this key
    pub fn group(&self) -> &SchnorrGroup {
        &self.g
    }

    /// Gets this key's shared value
    pub fn value(&self) -> &Integer {
        &self.h
    }

    fn validate(self) -> Option<Self> {
        if self.g.has_element(&self.h) {
            Some(self)
        } else {
            None
        }
    }
}

/// A builder for [SharedKey]
///
/// This builder constructs a [SharedKey] from several [PublicKey]s.
#[derive(Clone, Debug)]
pub struct SharedKeyBuilder {
    g: SchnorrGroup,
    h: Integer,
}

impl SharedKeyBuilder {
    /// Combines a new public key into this builder
    pub fn combine(&mut self, pk: &PublicKey) -> &mut Self {
        assert!(self.g == pk.g);
        self.h *= &pk.h;
        self
    }
}

impl From<PublicKey> for SharedKeyBuilder {
    fn from(pk: PublicKey) -> Self {
        Self { g: pk.g, h: pk.h }
    }
}

impl From<SharedKeyBuilder> for SharedKey {
    fn from(pk: SharedKeyBuilder) -> Self {
        // SAFE: a builder holds the same invariants as a shared key
        unsafe { Self::new_unchecked(pk.g, pk.h) }
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

impl<'de> Deserialize<'de> for SharedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { KeyRaw::deserialize(deserializer)?.into_shared() }
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

    unsafe fn into_shared(self) -> SharedKey {
        SharedKey::new_unchecked(self.g, self.i)
    }
}

/// A distribution that produces keys from a Schnorr group.
#[derive(Clone, Debug)]
pub struct Keys<'a>(&'a SchnorrGroup);

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
