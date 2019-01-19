//! Barnett and Smart's verifiable *k*-out-of-*k* Threshold Masking Function

use crate::{
    error::Error,
    group::Group,
    keys::{Fingerprint, PrivateKey, PublicKey},
    num::{fpowm, Modulo},
    perm::Permutation,
    zkp::{dlog_eq, mask_1ofn, secret_shuffle},
};
use pbmx_serde::{derive_base64_conversions, serialize_flat_map};
use rand::{thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;

pub use crate::zkp::{
    dlog_eq::Proof as MaskProof, mask_1ofn::Proof as PrivateMaskProof,
    secret_shuffle::Proof as ShuffleProof,
};

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Serialize)]
pub struct Vtmf {
    g: Group,
    sk: PrivateKey,
    pk: PublicKey,
    #[serde(serialize_with = "serialize_flat_map")]
    pki: HashMap<Fingerprint, PublicKey>,
}

/// A masked value
pub type Mask = (Integer, Integer);

/// One party's share of a secret
pub type SecretShare = Integer;

/// Zero-knowledge proof of a secret share
pub type SecretShareProof = MaskProof;

impl Vtmf {
    /// Creates a new VTMF with the given private key
    pub fn new(sk: PrivateKey) -> Self {
        let pk = sk.public_key();
        let group = sk.group().clone();
        // SAFE: we know all the values are consistent
        unsafe { Self::new_unchecked(group, sk, pk.clone(), vec![pk]) }
    }

    /// Add a public key to the VTMF
    pub fn add_key(&mut self, pk: PublicKey) -> Result<(), Error> {
        if pk.group() != self.sk.group() {
            return Err(Error::GroupMismatch);
        }

        self.pk.combine(&pk);
        self.pki.insert(pk.fingerprint(), pk);
        self.precompute();
        Ok(())
    }

    fn precompute(&self) {
        fpowm::precompute(&self.pk.element(), self.g.bits(), self.g.modulus()).unwrap();
    }

    unsafe fn new_unchecked(g: Group, sk: PrivateKey, pk: PublicKey, pki: Vec<PublicKey>) -> Self {
        let vtmf = Self {
            g,
            sk,
            pk,
            pki: pki.into_iter().map(|k| (k.fingerprint(), k)).collect(),
        };
        vtmf.precompute();
        vtmf
    }

    fn validate(self) -> Option<Self> {
        if self.g == *self.pk.group() && self.g == *self.sk.group() {
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
    /// Gets the group for this VTMF
    pub fn group(&self) -> &Group {
        &self.g
    }

    /// Gets the number of parties in this VTMF
    pub fn parties(&self) -> u32 {
        self.pki.len() as _
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
}

impl Vtmf {
    /// Obtains one share of a masking operation
    pub fn unmask_share(&self, c: &Mask) -> (SecretShare, SecretShareProof) {
        let g = self.g.generator();
        let p = self.g.modulus();
        let x = self.sk.exponent();

        let hi = self.g.element(x);
        let d = Integer::from(c.0.pow_mod_ref(x, p).unwrap());
        let proof = dlog_eq::prove(&self.g, &d, &hi, &c.0, g, x);

        (d, proof)
    }

    /// Verifies a secret share of a masking operation
    pub fn verify_unmask(
        &self,
        c: &Mask,
        pk_fp: &Fingerprint,
        d: &SecretShare,
        proof: &SecretShareProof,
    ) -> bool {
        let g = self.g.generator();
        let pk = self.pki.get(pk_fp);
        let pk = match pk {
            None => {
                return false;
            }
            Some(pk) => pk,
        };
        let h = pk.element();

        dlog_eq::verify(&self.g, d, h, &c.0, g, proof)
    }

    /// Undoes part of a masking operation
    pub fn unmask(&self, c: Mask, d: SecretShare) -> Mask {
        let p = self.g.modulus();

        let d1 = d.invert(&p).unwrap();
        (c.0, c.1 * d1 % p)
    }

    /// Privately undoes a masking operation
    pub fn unmask_private(&self, c: Mask) -> Integer {
        let d = self.unmask_share(&c).0;
        self.unmask(c, d).1
    }

    /// Undoes a non-secret masking operation
    pub fn unmask_open(&self, m: &Mask) -> Integer {
        m.1.clone()
    }
}

impl Vtmf {
    /// Applies the mask-shuffle protocol for a given permutation
    pub fn mask_shuffle(&self, m: &[Mask], pi: &Permutation) -> (Vec<Mask>, ShuffleProof) {
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
        // SAFE: we explicitly validate the values before returning
        unsafe { VtmfRaw::deserialize(deserializer)?.into() }
            .validate()
            .ok_or_else(|| de::Error::custom("invalid VTMF values"))
    }
}

#[derive(Deserialize)]
struct VtmfRaw {
    g: Group,
    sk: PrivateKey,
    pk: PublicKey,
    pki: Vec<PublicKey>,
}

impl VtmfRaw {
    unsafe fn into(self) -> Vtmf {
        Vtmf::new_unchecked(self.g, self.sk, self.pk, self.pki)
    }
}

derive_base64_conversions!(Vtmf, Error);

#[cfg(test)]
mod test {
    use super::Vtmf;
    use crate::{group::Groups, keys::Keys, num::Bits, perm::Shuffles};
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
        let (sk0, _) = rng.sample(&Keys(&group));
        let (_, pk1) = rng.sample(&Keys(&group));
        let (_, pk2) = rng.sample(&Keys(&group));
        let mut original = Vtmf::new(sk0);
        original.add_key(pk1).unwrap();
        original.add_key(pk2).unwrap();
        println!("vtmf = {}", original);

        let exported = original.to_string();

        let recovered = Vtmf::from_str(&exported).unwrap();

        assert_eq!(original.g, recovered.g);
        assert_eq!(original.sk, recovered.sk);
        assert_eq!(original.pk, recovered.pk);
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
        let (sk0, pk0) = rng.sample(&Keys(&group));
        let (sk1, pk1) = rng.sample(&Keys(&group));
        let mut vtmf0 = Vtmf::new(sk0);
        let fp0 = pk0.fingerprint();
        let mut vtmf1 = Vtmf::new(sk1);
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let x = rng.sample(&Bits(128));
        let (mask, proof) = vtmf0.mask(&x);
        let ok = vtmf1.verify_mask(&x, &mask, &proof);
        assert!(
            ok,
            "mask verification failed\n\tx = {}\n\tmask = {:?}\n\tproof = {:?}",
            x, mask, proof
        );

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let ok = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert!(ok, "share verification failed");
        let mask0 = vtmf0.unmask(mask.clone(), d1.clone());
        let r = vtmf0.unmask_private(mask0);
        assert_eq!(r, x);

        let ok = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert!(ok, "share verification failed");
        let mask1 = vtmf1.unmask(mask.clone(), d0);
        let mask1 = vtmf1.unmask(mask1, d1);
        let r = vtmf1.unmask_open(&mask1);
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
        let (sk0, pk0) = rng.sample(&Keys(&group));
        let (sk1, pk1) = rng.sample(&Keys(&group));
        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

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

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let ok = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert!(ok, "share verification failed");
        let mask0 = vtmf0.unmask(mask.clone(), d1);
        let r = vtmf0.unmask_private(mask0);
        assert_eq!(r, x);

        let ok = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert!(ok, "share verification failed");
        let mask1 = vtmf1.unmask(mask.clone(), d0);
        let r = vtmf1.unmask_private(mask1);
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
        let (sk0, pk0) = rng.sample(&Keys(&group));
        let (sk1, pk1) = rng.sample(&Keys(&group));
        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let x = rng.sample(&Bits(128));
        let mask = vtmf0.mask_open(&x);

        let open = vtmf1.unmask_open(&mask);
        assert_eq!(x, open);

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let ok = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert!(ok, "share verification failed");
        let mask0 = vtmf0.unmask(mask.clone(), d1);
        let r = vtmf0.unmask_private(mask0);
        assert_eq!(r, x);

        let ok = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert!(ok, "share verification failed");
        let mask1 = vtmf1.unmask(mask.clone(), d0);
        let r = vtmf1.unmask_private(mask1);
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
        let (sk0, pk0) = rng.sample(&Keys(&group));
        let (sk1, pk1) = rng.sample(&Keys(&group));
        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let m: Vec<_> = (1..8).map(Integer::from).collect();
        let idx = rng.gen_range(1, 7);
        let (mask, proof) = vtmf0.mask_private(&m, idx);
        let ok = vtmf1.verify_private_mask(&m, &mask, &proof);
        assert!(
            ok,
            "mask verification failed\n\tidx = {}\n\tmask = {:?}\n\tproof = {:?}",
            idx, mask, proof
        );

        let (d1, proof1) = vtmf1.unmask_share(&mask);
        let ok = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert!(ok, "share verification failed");
        let mask0 = vtmf0.unmask(mask, d1);
        let r = vtmf0.unmask_private(mask0);
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
        let (sk0, pk0) = rng.sample(&Keys(&group));
        let (sk1, pk1) = rng.sample(&Keys(&group));
        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let m: Vec<_> = (1..8)
            .map(Integer::from)
            .map(|i| vtmf0.mask(&i).0)
            .collect();
        let pi = thread_rng().sample(&Shuffles(m.len()));
        let (shuffle, proof) = vtmf0.mask_shuffle(&m, &pi);
        let ok = vtmf1.verify_mask_shuffle(&m, &shuffle, &proof);
        assert!(
            ok,
            "shuffle verification failed\n\toriginal = {:?}\n\tshuffle = {:?}\n\tproof = {:?}",
            m, shuffle, proof
        );

        let mut open: Vec<_> = shuffle
            .iter()
            .map(|s| {
                let (d1, proof1) = vtmf1.unmask_share(&s);
                let ok = vtmf0.verify_unmask(&s, &fp1, &d1, &proof1);
                assert!(ok, "share verification failed");
                let mask0 = vtmf0.unmask(s.clone(), d1);
                vtmf0.unmask_private(mask0)
            })
            .collect();
        open.sort();
        for (o, i) in open.into_iter().zip(1..8) {
            assert_eq!(o, Integer::from(i));
        }
    }
}
