//! Barnett and Smart's verifiable *k*-out-of-*k* Threshold Masking Function

use crate::{
    error::Error,
    group::Group,
    keys::{Fingerprint, PrivateKey, PublicKey},
    num::{fpowm, Modulo},
    perm::Shuffles,
    zkp::{dlog_eq, mask_1ofn, secret_shuffle},
};
use pbmx_util::{derive_base64_conversions, serde::serialize_flat_map};
use rand::{thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;

mod kex;
pub use self::kex::*;

mod dec;
pub use self::dec::*;

pub use crate::zkp::{
    dlog_eq::Proof as MaskProof, mask_1ofn::Proof as PrivateMaskProof,
    secret_shuffle::Proof as ShuffleProof,
};

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Serialize)]
pub struct Vtmf {
    g: Group,
    n: u32,
    sk: PrivateKey,
    pk: PublicKey,
    fp: Fingerprint,
    #[serde(serialize_with = "serialize_flat_map")]
    pki: HashMap<Fingerprint, PublicKey>,
}

/// A masked value
pub type Mask = (Integer, Integer);

impl Vtmf {
    unsafe fn new_unchecked(
        g: Group,
        n: u32,
        sk: PrivateKey,
        pk: PublicKey,
        fp: Fingerprint,
        pki: Vec<PublicKey>,
    ) -> Self {
        fpowm::precompute(&pk.element(), g.bits(), g.modulus()).unwrap();
        Self {
            g,
            n,
            sk,
            pk,
            fp,
            pki: pki.into_iter().map(|k| (k.fingerprint(), k)).collect(),
        }
    }

    fn validate(self) -> Option<Self> {
        if self.g == *self.pk.group() && self.g == *self.sk.group() && self.n > 1 {
            Some(self)
        } else {
            let p = self.g.modulus();

            let h = self
                .pki
                .values()
                .fold(Integer::from(1), |acc, pk| acc * pk.element() % p);
            if h == *self.pk.element() {
                Some(self)
            } else {
                None
            }
        }
    }
}

impl Vtmf {
    /// Applies a non-secret masking operation
    pub fn mask_open(&self, m: &Integer) -> Mask {
        (1.into(), m.into())
    }

    /// Applies the verifiable masking protocol
    pub fn mask(&self, m: &Integer) -> (Mask, MaskProof) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();
        let h = self.pk.element();

        let r = thread_rng().sample(&Modulo(q));
        let c1 = fpowm::pow_mod(g, &r, p).unwrap();
        let hr = fpowm::pow_mod(h, &r, p).unwrap();
        let proof = dlog_eq::prove(&self.g, &c1, &hr, g, h, &r);
        let c2 = hr * m % p;
        ((c1, c2), proof)
    }

    /// Verifies the application of the masking protocol
    pub fn verify_mask(&self, m: &Integer, c: &Mask, proof: &MaskProof) -> bool {
        let p = self.g.modulus();
        let g = self.g.generator();
        let h = self.pk.element();
        let m1 = Integer::from(m.invert_ref(p).unwrap());
        let hr = &c.1 * m1 % p;
        dlog_eq::verify(&self.g, &c.0, &hr, g, h, proof)
    }

    /// Applies a private masking operation from a given subset
    pub fn mask_private(&self, m: &[Integer], idx: usize) -> (Mask, PrivateMaskProof) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();
        let h = self.pk.element();

        let r = thread_rng().sample(&Modulo(q));
        let c1 = fpowm::pow_mod(g, &r, p).unwrap();
        let hr = fpowm::pow_mod(h, &r, p).unwrap();
        let c2 = hr * &m[idx] % p;

        let proof = mask_1ofn::prove(&self.g, &c1, &c2, g, h, m, idx, &r);
        ((c1, c2), proof)
    }

    /// Verifies the application of a private masking operation
    pub fn verify_private_mask(&self, m: &[Integer], c: &Mask, proof: &PrivateMaskProof) -> bool {
        let g = self.g.generator();
        let h = self.pk.element();
        mask_1ofn::verify(&self.g, &c.0, &c.1, g, h, m, proof)
    }

    /// Applies the verifiable re-masking protocol
    pub fn remask(&self, c: &Mask) -> (Mask, MaskProof) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();
        let h = self.pk.element();

        let r = thread_rng().sample(&Modulo(q));
        let gr = fpowm::pow_mod(g, &r, p).unwrap();
        let hr = fpowm::pow_mod(h, &r, p).unwrap();
        let proof = dlog_eq::prove(&self.g, &gr, &hr, g, h, &r);

        let c1 = gr * &c.0 % p;
        let c2 = hr * &c.1 % p;
        ((c1, c2), proof)
    }

    /// Verifies the application of the re-masking protocol
    pub fn verify_remask(&self, m: &Mask, c: &Mask, proof: &MaskProof) -> bool {
        let p = self.g.modulus();
        let g = self.g.generator();
        let h = self.pk.element();

        let c11 = Integer::from(m.0.invert_ref(p).unwrap());
        let gr = &c.0 * c11 % p;
        let c21 = Integer::from(m.1.invert_ref(p).unwrap());
        let hr = &c.1 * c21 % p;
        dlog_eq::verify(&self.g, &gr, &hr, g, h, proof)
    }

    /// Starts an instance of the verifiable decryption protocol
    pub fn unmask(&self, c: Mask) -> Decryption {
        Decryption::new(self, c)
    }

    /// Undoes a non-secret masking operation
    pub fn unmask_open(&self, m: &Mask) -> Option<Integer> {
        if m.0 == 1 {
            Some(m.1.clone())
        } else {
            None
        }
    }
}

impl Vtmf {
    /// Applies the mask-shuffle protocol.
    pub fn mask_shuffle(&self, m: &[Mask]) -> (Vec<Mask>, ShuffleProof) {
        let p = self.g.modulus();
        let q = self.g.order();
        let g = self.g.generator();
        let h = self.pk.element();

        let mut rng = thread_rng();

        let remask = |c: &Mask| {
            let r = rng.sample(&Modulo(q));
            let gr = fpowm::pow_mod(g, &r, p).unwrap();
            let hr = fpowm::pow_mod(h, &r, p).unwrap();

            let c1 = gr * &c.0 % p;
            let c2 = hr * &c.1 % p;
            ((c1, c2), r)
        };

        let (mut rm, mut r): (Vec<_>, Vec<_>) = m.iter().map(remask).unzip();
        let pi = rng.sample(&Shuffles(m.len()));
        pi.apply_to(&mut rm);
        pi.apply_to(&mut r);

        let proof = secret_shuffle::prove(&self.g, h, &rm, &pi, &r);
        (rm, proof)
    }

    /// Verifies the application of the mask-shuffling protocol
    pub fn verify_mask_shuffle(&self, m: &[Mask], c: &[Mask], proof: &ShuffleProof) -> bool {
        secret_shuffle::verify(m, c, proof)
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
            .ok_or_else(|| de::Error::custom("invalid VTMF values"))
    }
}

#[derive(Deserialize)]
struct VtmfRaw {
    g: Group,
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

derive_base64_conversions!(Vtmf, Error);

#[cfg(test)]
mod test {
    use super::{KeyExchange, Vtmf};
    use crate::{group::Groups, keys::Keys, num::Bits};
    use rand::{thread_rng, Rng};
    use rug::Integer;
    use std::str::FromStr;

    #[test]
    fn vtmf_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let dist = Groups {
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
    }

    #[test]
    fn vtmf_masking_and_unmasking_work() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let mut kex0 = KeyExchange::new(group.clone(), 2);
        let pk0 = kex0.generate_key().unwrap();
        let fp0 = pk0.fingerprint();
        let mut kex1 = KeyExchange::new(group, 2);
        let pk1 = kex1.generate_key().unwrap();
        let fp1 = pk1.fingerprint();
        kex0.update_key(pk1).unwrap();
        kex1.update_key(pk0).unwrap();
        let vtmf0 = kex0.finalize().unwrap();
        let vtmf1 = kex1.finalize().unwrap();

        let x = rng.sample(&Bits(128));
        let (mask, proof) = vtmf0.mask(&x);
        let ok = vtmf1.verify_mask(&x, &mask, &proof);
        assert!(
            ok,
            "mask verification failed\n\tx = {}\n\tmask = {:?}\n\tproof = {:?}",
            x, mask, proof
        );

        let mut dec0 = vtmf0.unmask(mask.clone());
        let mut dec1 = vtmf1.unmask(mask.clone());
        let (d0, proof0) = dec0.reveal_share().unwrap();
        let (d1, proof1) = dec1.reveal_share().unwrap();

        dec0.add_share(&fp1, &d1, &proof1).unwrap();
        assert!(dec0.is_complete());
        let r = dec0.decrypt().unwrap();
        assert_eq!(r, x);

        dec1.add_share(&fp0, &d0, &proof0).unwrap();
        assert!(dec1.is_complete());
        let r = dec1.decrypt().unwrap();
        assert_eq!(r, x);
    }

    #[test]
    fn vtmf_masking_remasking_and_unmasking_work() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let mut kex0 = KeyExchange::new(group.clone(), 2);
        let pk0 = kex0.generate_key().unwrap();
        let mut kex1 = KeyExchange::new(group, 2);
        let pk1 = kex1.generate_key().unwrap();
        let fp1 = pk1.fingerprint();
        kex0.update_key(pk1).unwrap();
        kex1.update_key(pk0).unwrap();
        let vtmf0 = kex0.finalize().unwrap();
        let vtmf1 = kex1.finalize().unwrap();

        let x = rng.sample(&Bits(128));
        let (mask, proof) = vtmf0.mask(&x);
        let ok = vtmf1.verify_mask(&x, &mask, &proof);
        assert!(
            ok,
            "mask verification failed\n\tx = {}\n\tmask = {:?}\n\tproof = {:?}",
            x, mask, proof
        );
        let (remask, proof) = vtmf0.remask(&mask);
        let ok = vtmf1.verify_remask(&mask, &remask, &proof);
        assert!(
            ok,
            "remask verification failed\n\tmask = {:?}\n\tremask = {:?}\n\tproof = {:?}",
            mask, remask, proof
        );

        let mut dec0 = vtmf0.unmask(mask.clone());
        let mut dec1 = vtmf1.unmask(mask.clone());
        let _ = dec0.reveal_share().unwrap();
        let (di, proof) = dec1.reveal_share().unwrap();
        dec0.add_share(&fp1, &di, &proof).unwrap();
        assert!(dec0.is_complete());
        let r = dec0.decrypt().unwrap();
        assert_eq!(r, x);
    }

    #[test]
    fn vtmf_open_masking_works() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let mut kex0 = KeyExchange::new(group.clone(), 2);
        let pk0 = kex0.generate_key().unwrap();
        let mut kex1 = KeyExchange::new(group, 2);
        let pk1 = kex1.generate_key().unwrap();
        let fp1 = pk1.fingerprint();
        kex0.update_key(pk1).unwrap();
        kex1.update_key(pk0).unwrap();
        let vtmf0 = kex0.finalize().unwrap();
        let vtmf1 = kex1.finalize().unwrap();

        let x = rng.sample(&Bits(128));
        let mask = vtmf0.mask_open(&x);

        let open = vtmf1.unmask_open(&mask);
        assert_eq!(Some(x.clone()), open);

        let mut dec0 = vtmf0.unmask(mask.clone());
        let mut dec1 = vtmf1.unmask(mask.clone());
        let _ = dec0.reveal_share().unwrap();
        let (di, proof) = dec1.reveal_share().unwrap();
        dec0.add_share(&fp1, &di, &proof).unwrap();
        assert!(dec0.is_complete());
        let r = dec0.decrypt().unwrap();
        assert_eq!(r, x);
    }

    #[test]
    fn vtmf_private_masking_works() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let mut kex0 = KeyExchange::new(group.clone(), 2);
        let pk0 = kex0.generate_key().unwrap();
        let mut kex1 = KeyExchange::new(group, 2);
        let pk1 = kex1.generate_key().unwrap();
        let fp1 = pk1.fingerprint();
        kex0.update_key(pk1).unwrap();
        kex1.update_key(pk0).unwrap();
        let vtmf0 = kex0.finalize().unwrap();
        let vtmf1 = kex1.finalize().unwrap();

        let m: Vec<_> = (1..8).map(Integer::from).collect();
        let idx = rng.gen_range(1, 7);
        let (mask, proof) = vtmf0.mask_private(&m, idx);
        let ok = vtmf1.verify_private_mask(&m, &mask, &proof);
        assert!(
            ok,
            "mask verification failed\n\tidx = {}\n\tmask = {:?}\n\tproof = {:?}",
            idx, mask, proof
        );

        let mut dec0 = vtmf0.unmask(mask.clone());
        let mut dec1 = vtmf1.unmask(mask.clone());
        let _ = dec0.reveal_share().unwrap();
        let (di, proof) = dec1.reveal_share().unwrap();
        dec0.add_share(&fp1, &di, &proof).unwrap();
        assert!(dec0.is_complete());
        let r = dec0.decrypt().unwrap();
        assert_eq!(r, m[idx]);
    }

    #[test]
    fn vtmf_mask_shuffling_works() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let mut kex0 = KeyExchange::new(group.clone(), 2);
        let pk0 = kex0.generate_key().unwrap();
        let mut kex1 = KeyExchange::new(group, 2);
        let pk1 = kex1.generate_key().unwrap();
        let fp1 = pk1.fingerprint();
        kex0.update_key(pk1).unwrap();
        kex1.update_key(pk0).unwrap();
        let vtmf0 = kex0.finalize().unwrap();
        let vtmf1 = kex1.finalize().unwrap();

        let m: Vec<_> = (1..8)
            .map(Integer::from)
            .map(|i| vtmf0.mask(&i).0)
            .collect();
        let (shuffle, proof) = vtmf0.mask_shuffle(&m);
        let ok = vtmf1.verify_mask_shuffle(&m, &shuffle, &proof);
        assert!(
            ok,
            "shuffle verification failed\n\toriginal = {:?}\n\tshuffle = {:?}\n\tproof = {:?}",
            m, shuffle, proof
        );

        let mut open: Vec<_> = shuffle
            .iter()
            .map(|s| {
                let mut dec0 = vtmf0.unmask(s.clone());
                let mut dec1 = vtmf1.unmask(s.clone());
                let _ = dec0.reveal_share().unwrap();
                let (di, proof) = dec1.reveal_share().unwrap();
                dec0.add_share(&fp1, &di, &proof).unwrap();
                assert!(dec0.is_complete());
                dec0.decrypt().unwrap()
            })
            .collect();
        open.sort();
        for (o, i) in open.into_iter().zip(1..8) {
            assert_eq!(o, Integer::from(i));
        }
    }
}
