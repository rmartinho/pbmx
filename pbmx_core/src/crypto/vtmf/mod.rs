use crate::{
    crypto::key::{PrivateKey, PublicKey},
    num::{fpowm::FastPowModTable, integer::Modulo, schnorr::SchnorrGroup},
};
use rand::{thread_rng, Rng};
use rug::Integer;

mod kex;
pub use self::kex::*;

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Serialize)] // TODO Deserialize
pub struct Vtmf {
    g: SchnorrGroup,
    sk: PrivateKey,
    pk: PublicKey,

    #[serde(skip)]
    fpowm: FastPowModTable,
}

impl Vtmf {
    /// Creates a new VTMF
    unsafe fn new_unchecked(g: SchnorrGroup, sk: PrivateKey, pk: PublicKey) -> Self {
        Self {
            fpowm: FastPowModTable::new(g.order().significant_bits(), g.modulus(), g.generator()),
            g,
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

    /// Publishing step of the verifiable decryption protocol
    pub fn reveal_mask(&self, c: &(Integer, Integer)) -> Integer {
        let p = self.g.modulus();

        Integer::from(c.0.pow_mod_ref(&self.sk.x, p).unwrap())
    }

    /// Accumulate step of the verifiable decryption protocol
    pub fn accumulate_mask(&self, d: &mut Integer, di: &Integer) {
        *d *= di;
    }

    /// Decrypting step of the verifiable decryption protocol
    pub fn decrypt(&self, c: &(Integer, Integer), d: &Integer) -> Integer {
        let p = self.g.modulus();
        let d1 = Integer::from(d.invert_ref(&p).unwrap());

        &c.1 * d1
    }
}
