use crate::{
    crypto::key::{PrivateKey, PublicKey},
    num::{fpowm::FastPowModTable, integer::Modulo, schnorr::SchnorrGroup},
};
use rand::{thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};

mod kex;
pub use self::kex::*;

mod dec;
pub use self::dec::*;

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Serialize)]
pub struct Vtmf {
    g: SchnorrGroup,
    n: u32,
    sk: PrivateKey,
    pk: PublicKey,

    #[serde(skip)]
    fpowm: FastPowModTable,
}

impl Vtmf {
    unsafe fn new_unchecked(g: SchnorrGroup, n: u32, sk: PrivateKey, pk: PublicKey) -> Self {
        Self {
            fpowm: FastPowModTable::new(g.order().significant_bits(), g.modulus(), g.generator()),
            g,
            n,
            sk,
            pk,
        }
    }

    /// Applies the verifiable masking protocol
    pub fn mask(&self, m: &Integer) -> (Integer, Integer) {
        let p = self.g.modulus();
        let q = self.g.order();
        let r = thread_rng().sample(&Modulo(q));

        let c1 = self.g.element(&r);
        let c2 = self.fpowm.pow_mod(&r).unwrap() * m % p;
        (c1, c2)
    }

    /// Applies the verifiable masking protocol
    pub fn remask(&self, c: &(Integer, Integer)) -> (Integer, Integer) {
        let p = self.g.modulus();
        let q = self.g.order();
        let r = thread_rng().sample(&Modulo(q));

        let c1 = self.g.element(&r) * &c.0 % p;
        let c2 = self.fpowm.pow_mod(&r).unwrap() * &c.1 % p;
        (c1, c2)
    }

    /// Starts one instance of the verifiable decryption protocol
    pub fn unmask(&self, c: (Integer, Integer)) -> Decryption {
        Decryption::new(self, c)
    }

    fn validate(self) -> Option<Self> {
        if self.g == self.pk.g && self.g == self.sk.g && self.n > 1 {
            Some(self)
        } else {
            None
        }
    }
}

impl<'de> Deserialize<'de> for Vtmf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { VtmfRaw::deserialize(deserializer)?.into() }
            .validate()
            .ok_or(de::Error::custom("invalid VTMF values"))
    }
}

#[derive(Deserialize)]
struct VtmfRaw {
    g: SchnorrGroup,
    n: u32,
    sk: PrivateKey,
    pk: PublicKey,
}

impl VtmfRaw {
    unsafe fn into(self) -> Vtmf {
        Vtmf::new_unchecked(self.g, self.n, self.sk, self.pk)
    }
}
