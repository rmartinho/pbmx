use crate::{
    crypto::key::{Fingerprint, PrivateKey, PublicKey},
    num::{fpowm::FastPowModTable, integer::Modulo, schnorr::SchnorrGroup},
};
use rand::{thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

mod kex;
pub use self::kex::*;

mod dec;
pub use self::dec::*;

mod cp;

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Serialize)]
pub struct Vtmf {
    g: SchnorrGroup,
    n: u32,
    sk: PrivateKey,
    pk: PublicKey,
    fp: Fingerprint,
    #[serde(serialize_with = "serialize_key_shares_flat")]
    pki: HashMap<Fingerprint, PublicKey>,

    #[serde(skip)]
    fpowm: FastPowModTable,
}

/// A zero-knownledge proof
pub type Proof = (Integer, Integer);
/// A masked value
pub type Mask = (Integer, Integer);

impl Vtmf {
    unsafe fn new_unchecked(
        g: SchnorrGroup,
        n: u32,
        sk: PrivateKey,
        pk: PublicKey,
        fp: Fingerprint,
        pki: Vec<PublicKey>,
    ) -> Self {
        Self {
            fpowm: FastPowModTable::new(g.order().significant_bits(), g.modulus(), g.generator()),
            g,
            n,
            sk,
            pk,
            fp,
            pki: pki.into_iter().map(|k| (k.fingerprint(), k)).collect(),
        }
    }

    /// Applies the verifiable masking protocol
    pub fn mask(&self, m: &Integer) -> (Mask, Proof) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();
        let h = &self.pk.h;

        let r = thread_rng().sample(&Modulo(q));
        let c1 = self.g.element(&r);
        let hr = self.fpowm.pow_mod(&r).unwrap();
        let proof = cp::prove(self, &c1, &hr, g, h, &r);
        let c2 = hr * m % p;
        ((c1, c2), proof)
    }

    /// Verifies the application of the masking protocol
    pub fn verify_mask(&self, m: &Integer, c: &Mask, proof: &Proof) -> bool {
        let p = self.g.modulus();
        let g = self.g.generator();
        let h = &self.pk.h;
        let m1 = Integer::from(m.invert_ref(p).unwrap());
        let hr = &c.1 * m1;
        cp::verify(self, &c.0, &hr, g, h, proof)
    }

    /// Applies the verifiable re-masking protocol
    pub fn remask(&self, c: &Mask) -> (Mask, Proof) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();
        let h = &self.pk.h;

        let r = thread_rng().sample(&Modulo(q));
        let gr = self.g.element(&r);
        let hr = self.fpowm.pow_mod(&r).unwrap();
        let proof = cp::prove(self, &gr, &hr, g, h, &r);

        let c1 = gr * &c.0 % p;
        let c2 = hr * &c.1 % p;
        ((c1, c2), proof)
    }

    /// Verifies the application of the re-masking protocol
    pub fn verify_remask(&self, m: &Mask, c: &Mask, proof: &Proof) -> bool {
        let p = self.g.modulus();
        let g = self.g.generator();
        let h = &self.pk.h;

        let c11 = Integer::from(m.0.invert_ref(p).unwrap());
        let gr = &c.0 * c11;
        let c21 = Integer::from(m.1.invert_ref(p).unwrap());
        let hr = &c.1 * c21;
        cp::verify(self, &gr, &hr, g, h, proof)
    }

    /// Starts an instance of the verifiable decryption protocol
    pub fn unmask(&self, c: Mask) -> Decryption {
        Decryption::new(self, c)
    }

    fn validate(self) -> Option<Self> {
        if self.g == self.pk.g && self.g == self.sk.g && self.n > 1 {
            Some(self)
        } else {
            let p = self.g.modulus();

            let h = self
                .pki
                .values()
                .fold(Integer::from(1), |acc, pk| acc * &pk.h % p);
            if h == self.pk.h {
                Some(self)
            } else {
                None
            }
        }
    }
}

fn serialize_key_shares_flat<S>(
    map: &HashMap<Fingerprint, PublicKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let v: Vec<_> = map.values().collect();
    v.serialize(serializer)
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
    fp: Fingerprint,
    pki: Vec<PublicKey>,
}

impl VtmfRaw {
    unsafe fn into(self) -> Vtmf {
        Vtmf::new_unchecked(self.g, self.n, self.sk, self.pk, self.fp, self.pki)
    }
}

derive_base64_conversions!(Vtmf);

#[cfg(test)]
mod test {
    use super::{KeyExchange, Vtmf};
    use crate::{crypto::key::Keys, num::schnorr::Schnorr};
    use rand::{thread_rng, Rng};
    use std::str::FromStr;

    #[test]
    fn vtmf_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (_, pk1) = rng.sample(&Keys(&group));
        let (_, pk2) = rng.sample(&Keys(&group));
        let mut kex = KeyExchange::new(group, 3);
        let _ = kex.generate_key().unwrap();
        kex.update_key(pk1).unwrap();
        kex.update_key(pk2).unwrap();
        let original = kex.finalize().unwrap();
        println!("vtmf = {}", original);

        let exported = original.to_string();

        let recovered = Vtmf::from_str(&exported).unwrap();

        assert_eq!(original.g, recovered.g);
        assert_eq!(original.n, recovered.n);
        assert_eq!(original.sk, recovered.sk);
        assert_eq!(original.pk, recovered.pk);
        assert_eq!(original.fp, recovered.fp);
        assert_eq!(original.pki, recovered.pki);
        assert_eq!(original.fpowm, recovered.fpowm);
    }
}
