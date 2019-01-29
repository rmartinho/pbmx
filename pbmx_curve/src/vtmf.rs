//! Barnett and Smart's verifiable *k*-out-of-*k* Threshold Masking Function

use crate::{
    error::Error,
    keys::{Fingerprint, PrivateKey, PublicKey},
    perm::Permutation,
    zkp::{dlog_eq, mask_1ofn, secret_rotation, secret_shuffle},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use pbmx_serde::{derive_base64_conversions, serialize_flat_map};
use rand::thread_rng;
use serde::{de, Deserialize, Deserializer};
use std::{collections::HashMap, sync::Mutex};

pub use crate::zkp::{
    dlog_eq::Proof as MaskProof, mask_1ofn::Proof as PrivateMaskProof,
    secret_rotation::Proof as ShiftProof, secret_shuffle::Proof as ShuffleProof,
};

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Serialize)]
pub struct Vtmf {
    sk: PrivateKey,
    pk: PublicKey,
    #[serde(serialize_with = "serialize_flat_map")]
    pki: HashMap<Fingerprint, PublicKey>,
}

/// A masked value
pub type Mask = (RistrettoPoint, RistrettoPoint);

/// One party's share of a secret
pub type SecretShare = RistrettoPoint;

/// Zero-knowledge proof of a secret share
pub type SecretShareProof = MaskProof;

impl Vtmf {
    /// Creates a new VTMF with the given private key
    pub fn new(sk: PrivateKey) -> Self {
        let pk = sk.public_key();
        // SAFE: we know all the values are consistent
        unsafe { Self::new_unchecked(sk, pk.clone(), vec![pk]) }
    }

    /// Add a public key to the VTMF
    pub fn add_key(&mut self, pk: PublicKey) -> Result<(), Error> {
        self.pk.combine(&pk);
        self.pki.insert(pk.fingerprint(), pk);
        Ok(())
    }

    unsafe fn new_unchecked(sk: PrivateKey, pk: PublicKey, pki: Vec<PublicKey>) -> Self {
        Self {
            sk,
            pk,
            pki: pki.into_iter().map(|k| (k.fingerprint(), k)).collect(),
        }
    }

    fn validate(self) -> Option<Self> {
        let fp = self.sk.public_key().fingerprint();
        if !self.pki.contains_key(&fp) {
            return None;
        }
        let h = self
            .pki
            .values()
            .map(PublicKey::point)
            .sum::<RistrettoPoint>();
        if h == *self.pk.point() {
            Some(self)
        } else {
            None
        }
    }
}

impl Vtmf {
    /// Gets the number of parties in this VTMF
    pub fn parties(&self) -> u32 {
        self.pki.len() as _
    }
}

impl Vtmf {
    /// Applies a non-secret masking operation
    pub fn mask_open(&self, m: &Scalar) -> Mask {
        (RistrettoPoint::identity(), G * m)
    }

    /// Applies the verifiable masking protocol
    pub fn mask(&self, m: &Scalar) -> (Mask, MaskProof) {
        let h = self.pk.point();
        let r = Scalar::random(&mut thread_rng());
        let c0 = G * &r;
        let hr = h * r;
        let c1 = hr + G * m;
        let proof = MaskProof::create(
            &mut Transcript::new(b"mask"),
            dlog_eq::Publics {
                a: &c0,
                b: &hr,
                g: &G.basepoint(),
                h,
            },
            dlog_eq::Secrets { x: &r },
        );
        ((c0, c1), proof)
    }

    /// Verifies the application of the masking protocol
    pub fn verify_mask(&self, m: &Scalar, c: &Mask, proof: &MaskProof) -> Result<(), ()> {
        proof.verify(&mut Transcript::new(b"mask"), dlog_eq::Publics {
            a: &c.0,
            b: &(c.1 - G * m),
            g: &G.basepoint(),
            h: self.pk.point(),
        })
    }

    /// Applies a private masking operation from a given subset
    pub fn mask_private(&self, m: &[Scalar], i: usize) -> (Mask, PrivateMaskProof) {
        let h = self.pk.point();
        let r = Scalar::random(&mut thread_rng());
        let c0 = G * &r;
        let c1 = h * r + G * &m[i];

        let proof = PrivateMaskProof::create(
            &mut Transcript::new(b"mask_private"),
            mask_1ofn::Publics {
                a: &c0,
                b: &c1,
                g: &G.basepoint(),
                h,
                m,
            },
            mask_1ofn::Secrets { x: &r, i },
        );
        ((c0, c1), proof)
    }

    /// Verifies the application of a private masking operation
    pub fn verify_private_mask(
        &self,
        m: &[Scalar],
        c: &Mask,
        proof: &PrivateMaskProof,
    ) -> Result<(), ()> {
        proof.verify(&mut Transcript::new(b"mask_private"), mask_1ofn::Publics {
            a: &c.0,
            b: &c.1,
            g: &G.basepoint(),
            h: self.pk.point(),
            m,
        })
    }

    /// Applies the verifiable re-masking protocol
    pub fn remask(&self, c: &Mask) -> (Mask, MaskProof) {
        let h = self.pk.point();
        let r = Scalar::random(&mut thread_rng());
        let gr = G * &r;
        let hr = h * r;
        let proof = MaskProof::create(
            &mut Transcript::new(b"remask"),
            dlog_eq::Publics {
                a: &gr,
                b: &hr,
                g: &G.basepoint(),
                h,
            },
            dlog_eq::Secrets { x: &r },
        );

        let c0 = gr + c.0;
        let c1 = hr + c.1;
        ((c0, c1), proof)
    }

    /// Verifies the application of the re-masking protocol
    pub fn verify_remask(&self, m: &Mask, c: &Mask, proof: &MaskProof) -> Result<(), ()> {
        let h = self.pk.point();
        let gr = c.0 - m.0;
        let hr = c.1 - m.1;
        proof.verify(&mut Transcript::new(b"remask"), dlog_eq::Publics {
            a: &gr,
            b: &hr,
            g: &G.basepoint(),
            h,
        })
    }
}

impl Vtmf {
    /// Obtains one share of a masking operation
    pub fn unmask_share(&self, c: &Mask) -> (SecretShare, SecretShareProof) {
        let x = self.sk.exponent();

        let d = c.0 * x;
        let proof = MaskProof::create(
            &mut Transcript::new(b"mask_share"),
            dlog_eq::Publics {
                a: &d,
                b: &(G * x),
                g: &c.0,
                h: &G.basepoint(),
            },
            dlog_eq::Secrets { x },
        );

        (d, proof)
    }

    /// Verifies a secret share of a masking operation
    pub fn verify_unmask(
        &self,
        c: &Mask,
        pk_fp: &Fingerprint,
        d: &SecretShare,
        proof: &SecretShareProof,
    ) -> Result<(), ()> {
        let pk = self.pki.get(pk_fp);
        let pk = match pk {
            None => {
                return Err(());
            }
            Some(pk) => pk,
        };
        proof.verify(&mut Transcript::new(b"mask_share"), dlog_eq::Publics {
            a: &d,
            b: &pk.point(),
            g: &c.0,
            h: &G.basepoint(),
        })
    }

    /// Undoes part of a masking operation
    pub fn unmask(&self, c: Mask, d: SecretShare) -> Mask {
        (c.0, c.1 - d)
    }

    /// Privately undoes a masking operation
    pub fn unmask_private(&self, c: Mask) -> Mask {
        let d = self.unmask_share(&c).0;
        self.unmask(c, d)
    }

    /// Undoes a non-secret masking operation
    pub fn unmask_open(&self, m: &Mask) -> Option<Scalar> {
        get_scalar_for(&m.1)
    }
}

impl Vtmf {
    /// Applies the mask-shuffle protocol for a given permutation
    pub fn mask_shuffle(&self, m: &[Mask], pi: &Permutation) -> (Vec<Mask>, ShuffleProof) {
        let mut rng = thread_rng();

        let h = self.pk.point();

        let remask = |c: &Mask| {
            let r = Scalar::random(&mut rng);

            let c1 = G * &r + c.0;
            let c2 = h * r + c.1;
            ((c1, c2), r)
        };

        let (mut rm, mut r): (Vec<_>, Vec<_>) = m.iter().map(remask).unzip();
        pi.apply_to(&mut rm);
        pi.apply_to(&mut r);

        let proof = ShuffleProof::create(
            &mut Transcript::new(b"mask_shuffle"),
            secret_shuffle::Publics {
                h: &h,
                e0: m,
                e1: &rm,
            },
            secret_shuffle::Secrets { pi: &pi, r: &r },
        );
        (rm, proof)
    }

    /// Verifies the application of the mask-shuffling protocol
    pub fn verify_mask_shuffle(
        &self,
        m: &[Mask],
        c: &[Mask],
        proof: &ShuffleProof,
    ) -> Result<(), ()> {
        proof.verify(
            &mut Transcript::new(b"mask_shuffle"),
            secret_shuffle::Publics {
                h: &self.pk.point(),
                e0: m,
                e1: c,
            },
        )
    }
}

impl Vtmf {
    /// Applies the mask-shuffle protocol for a given permutation
    pub fn mask_shift(&self, m: &[Mask], k: usize) -> (Vec<Mask>, ShiftProof) {
        let mut rng = thread_rng();

        let h = self.pk.point();

        let remask = |c: &Mask| {
            let r = Scalar::random(&mut rng);

            let c1 = G * &r + c.0;
            let c2 = h * r + c.1;
            ((c1, c2), r)
        };

        let (mut rm, mut r): (Vec<_>, Vec<_>) = m.iter().map(remask).unzip();
        let pi = Permutation::shift(m.len(), k);
        pi.apply_to(&mut rm);
        pi.apply_to(&mut r);

        let proof = ShiftProof::create(
            &mut Transcript::new(b"mask_shift"),
            secret_rotation::Publics {
                h: &h,
                e0: m,
                e1: &rm,
            },
            secret_rotation::Secrets { k, r: &r },
        );
        (rm, proof)
    }

    /// Verifies the application of the mask-shuffling protocol
    pub fn verify_mask_shift(&self, m: &[Mask], c: &[Mask], proof: &ShiftProof) -> Result<(), ()> {
        proof.verify(
            &mut Transcript::new(b"mask_shift"),
            secret_rotation::Publics {
                h: &self.pk.point(),
                e0: m,
                e1: c,
            },
        )
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
    sk: PrivateKey,
    pk: PublicKey,
    pki: Vec<PublicKey>,
}

impl VtmfRaw {
    unsafe fn into(self) -> Vtmf {
        Vtmf::new_unchecked(self.sk, self.pk, self.pki)
    }
}

derive_base64_conversions!(Vtmf, Error);

#[cfg(test)]
mod tests {
    use super::Vtmf;
    use crate::{
        keys::PrivateKey,
        perm::{Permutation, Shuffles},
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::{thread_rng, Rng};
    use std::str::FromStr;

    #[test]
    fn vtmf_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let sk2 = PrivateKey::random(&mut rng);
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let mut original = Vtmf::new(sk0);
        original.add_key(pk1).unwrap();
        original.add_key(pk2).unwrap();

        let exported = original.to_string();
        dbg!(&exported);

        let recovered = Vtmf::from_str(&exported).unwrap();

        assert_eq!(original.sk, recovered.sk);
        assert_eq!(original.pk, recovered.pk);
        assert_eq!(original.pki, recovered.pki);
    }

    #[test]
    fn vtmf_masking_and_unmasking_work() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let x = Scalar::from(rng.gen_range(0, 16) as u64);
        let (mask, proof) = vtmf0.mask(&x);
        let verified = vtmf1.verify_mask(&x, &mask, &proof);
        assert_eq!(verified, Ok(()));

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let verified = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert_eq!(verified, Ok(()));
        let mask0 = vtmf0.unmask(mask, d1);
        let mask0 = vtmf0.unmask_private(mask0);
        let r = vtmf1.unmask_open(&mask0);
        assert_eq!(r, Some(x));

        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let mask1 = vtmf1.unmask(mask, d0);
        let mask1 = vtmf1.unmask_private(mask1);
        let r = vtmf1.unmask_open(&mask1);
        assert_eq!(r, Some(x));
    }

    #[test]
    fn vtmf_masking_remasking_and_unmasking_work() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let x = Scalar::from(rng.gen_range(0, 16) as u64);
        let (mask, proof) = vtmf0.mask(&x);
        let verified = vtmf1.verify_mask(&x, &mask, &proof);
        assert_eq!(verified, Ok(()));

        let (remask, proof) = vtmf0.remask(&mask);
        let verified = vtmf1.verify_remask(&mask, &remask, &proof);
        assert_eq!(verified, Ok(()));

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let verified = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert_eq!(verified, Ok(()));
        let mask0 = vtmf0.unmask(mask, d1);
        let mask0 = vtmf0.unmask_private(mask0);
        let r = vtmf1.unmask_open(&mask0);
        assert_eq!(r, Some(x));

        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let mask1 = vtmf1.unmask(mask, d0);
        let mask1 = vtmf1.unmask_private(mask1);
        let r = vtmf1.unmask_open(&mask1);
        assert_eq!(r, Some(x));
    }

    #[test]
    fn vtmf_open_masking_works() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let x = Scalar::from(rng.gen_range(0, 16) as u64);
        let mask = vtmf0.mask_open(&x);

        let open = vtmf1.unmask_open(&mask);
        assert_eq!(open, Some(x));

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let verified = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert_eq!(verified, Ok(()));
        let mask0 = vtmf0.unmask(mask, d1);
        let mask0 = vtmf0.unmask_private(mask0);
        let r = vtmf1.unmask_open(&mask0);
        assert_eq!(r, Some(x));

        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let mask1 = vtmf1.unmask(mask, d0);
        let mask1 = vtmf1.unmask_private(mask1);
        let r = vtmf1.unmask_open(&mask1);
        assert_eq!(r, Some(x));
    }

    #[test]
    fn vtmf_private_masking_works() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let m: Vec<_> = (0u64..8).map(Scalar::from).collect();
        let i = rng.gen_range(0, 8);

        let (mask, proof) = vtmf0.mask_private(&m, i);
        let verified = vtmf1.verify_private_mask(&m, &mask, &proof);
        assert_eq!(verified, Ok(()));

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let mask1 = vtmf1.unmask(mask, d0);
        let mask1 = vtmf1.unmask_private(mask1);
        let r = vtmf1.unmask_open(&mask1);
        assert_eq!(r, Some(m[i]));
    }

    #[test]
    fn vtmf_mask_shuffling_works() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let m: Vec<_> = (0u64..8)
            .map(Scalar::from)
            .map(|i| vtmf0.mask(&i).0)
            .collect();
        let pi = thread_rng().sample(&Shuffles(m.len()));
        let (shuffle, proof) = vtmf0.mask_shuffle(&m, &pi);
        let verified = vtmf1.verify_mask_shuffle(&m, &shuffle, &proof);
        assert_eq!(verified, Ok(()));

        let open: Vec<_> = shuffle
            .iter()
            .map(|m| {
                let (d0, proof0) = vtmf0.unmask_share(m);
                let verified = vtmf1.verify_unmask(m, &fp0, &d0, &proof0);
                assert_eq!(verified, Ok(()));
                let mask1 = vtmf1.unmask(*m, d0);
                let mask1 = vtmf1.unmask_private(mask1);
                vtmf1.unmask_open(&mask1).unwrap()
            })
            .collect();
        let mut expected: Vec<_> = (0u64..8).map(Scalar::from).collect();
        pi.apply_to(&mut expected);
        assert_eq!(open, expected);
    }

    #[test]
    fn vtmf_mask_shifting_works() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        vtmf0.add_key(pk1).unwrap();
        vtmf1.add_key(pk0).unwrap();

        let m: Vec<_> = (0u64..8)
            .map(Scalar::from)
            .map(|i| vtmf0.mask(&i).0)
            .collect();
        let k = thread_rng().gen_range(0, 8);
        let (shift, proof) = vtmf0.mask_shift(&m, k);
        let verified = vtmf1.verify_mask_shift(&m, &shift, &proof);
        assert_eq!(verified, Ok(()));

        let open: Vec<_> = shift
            .iter()
            .map(|m| {
                let (d0, proof0) = vtmf0.unmask_share(m);
                let verified = vtmf1.verify_unmask(m, &fp0, &d0, &proof0);
                assert_eq!(verified, Ok(()));
                let mask1 = vtmf1.unmask(*m, d0);
                let mask1 = vtmf1.unmask_private(mask1);
                vtmf1.unmask_open(&mask1).unwrap()
            })
            .collect();
        let mut expected: Vec<_> = (0u64..8).map(Scalar::from).collect();
        let pi = Permutation::shift(8, k);
        pi.apply_to(&mut expected);
        assert_eq!(open, expected);
    }
}

lazy_static! {
    static ref POINT_MAP: Mutex<Vec<(Scalar, RistrettoPoint)>> = Mutex::new(Vec::new());
}
const MAX_POINTS_MAPPED: usize = 2048;

fn get_scalar_for(point: &RistrettoPoint) -> Option<Scalar> {
    match POINT_MAP.lock() {
        Ok(mut map) => match map.iter().find(|(_, p)| p == point) {
            None => loop {
                if map.len() >= MAX_POINTS_MAPPED {
                    return None;
                }

                let s = Scalar::from(map.len() as u64);
                let p = G * &s;
                map.push((s, p));

                if p == *point {
                    return Some(s);
                }
            },
            Some((s, _)) => Some(*s),
        },
        _ => None,
    }
}