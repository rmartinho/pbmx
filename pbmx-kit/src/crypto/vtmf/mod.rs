//! Verifiable *k*-out-of-*k* Threshold Masking Function

// [BS03] Adam Barnett, Nigel P. Smart:
//          'Mental Poker Revisited',
//          Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003
use crate::{
    crypto::{
        hash::{Transcribe, TranscriptAppend, TranscriptHash},
        keys::{Fingerprint, PrivateKey, PublicKey},
        perm::Permutation,
        proofs::{dlog_eq, entanglement, secret_rotation, secret_shuffle},
    },
    proto,
    random::thread_rng,
    serde::{point_from_proto, point_to_proto, Proto},
    Error, Result,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use digest::XofReader;
use merlin::Transcript;
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, iter};

pub use crate::crypto::proofs::{
    dlog_eq::Proof as MaskProof, entanglement::Proof as EntanglementProof,
    secret_rotation::Proof as ShiftProof, secret_shuffle::Proof as ShuffleProof,
};

mod mask;
pub use mask::*;
mod stack;
pub use stack::*;

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// A verifiable *k*-out-of-*k* threshold masking function
#[derive(Debug)]
pub struct Vtmf {
    sk: PrivateKey,
    pk: PublicKey,
    pki: HashMap<Fingerprint, PublicKey>,
}

/// One party's share of a secret
#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub struct SecretShare(pub(crate) RistrettoPoint);

impl Proto for SecretShare {
    type Message = proto::SecretShare;

    fn to_proto(&self) -> Result<proto::SecretShare> {
        Ok(proto::SecretShare {
            point: point_to_proto(&self.0)?,
        })
    }

    fn from_proto(m: &proto::SecretShare) -> Result<Self> {
        Ok(Self(point_from_proto(&m.point)?))
    }
}

impl Transcribe for SecretShare {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        b"share".append_to_transcript(t, label);
        self.0.append_to_transcript(t, b"c1xi");
    }
}

/// Zero-knowledge proof of a secret share
pub type SecretShareProof = MaskProof;

impl Vtmf {
    /// Creates a new VTMF with the given private key
    pub fn new(sk: PrivateKey) -> Self {
        let pk = sk.public_key();
        Self {
            sk,
            pk: pk.clone(),
            pki: vec![(pk.fingerprint(), pk)].into_iter().collect(),
        }
    }

    /// Gets the private key
    pub fn private_key(&self) -> PrivateKey {
        self.sk.clone()
    }

    /// Gets the public key
    pub fn public_key(&self) -> PublicKey {
        self.sk.public_key()
    }

    /// Gets the shared public key
    pub fn shared_key(&self) -> PublicKey {
        self.pk.clone()
    }

    /// Add a public key to the VTMF
    pub fn add_key(&mut self, pk: PublicKey) {
        let fp = pk.fingerprint();
        if self.pki.contains_key(&fp) {
            return;
        }
        self.pk.combine(&pk);
        self.pki.insert(fp, pk);
    }
}

impl Vtmf {
    /// Gets the number of parties in this VTMF
    pub fn parties(&self) -> usize {
        self.pki.len()
    }

    /// Gets the fingerprints of the parties in this VTMF
    pub fn fingerprints<'a>(&'a self) -> impl Iterator<Item = Fingerprint> + 'a {
        self.pki.keys().cloned()
    }

    /// Gets the public keys of the parties in this VTMF
    pub fn public_keys<'a>(&'a self) -> impl Iterator<Item = PublicKey> + 'a {
        self.pki.values().cloned()
    }
}

impl Vtmf {
    /// Applies the verifiable masking protocol
    pub fn mask(&self, p: &RistrettoPoint) -> (Mask, Scalar, MaskProof) {
        let h = self.pk.point();
        let r = Scalar::random(&mut thread_rng());
        let c0 = G * &r;
        let hr = h * r;
        let c1 = hr + p;
        let proof = MaskProof::create(
            &mut Transcript::new(b"mask"),
            dlog_eq::Publics {
                a: &c0,
                b: &hr,
                g: &G.basepoint(),
                h: &h,
            },
            dlog_eq::Secrets { x: &r },
        );
        (Mask(c0, c1), r, proof)
    }

    /// Verifies the application of the masking protocol
    pub fn verify_mask(&self, p: &RistrettoPoint, c: &Mask, proof: &MaskProof) -> Result<()> {
        proof.verify(&mut Transcript::new(b"mask"), dlog_eq::Publics {
            a: &c.0,
            b: &(c.1 - p),
            g: &G.basepoint(),
            h: &self.pk.point(),
        })
    }

    /// Applies the verifiable re-masking protocol
    pub fn remask(&self, c: &Mask) -> (Mask, Scalar, MaskProof) {
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
                h: &h,
            },
            dlog_eq::Secrets { x: &r },
        );

        let c0 = gr + c.0;
        let c1 = hr + c.1;
        (Mask(c0, c1), r, proof)
    }

    /// Verifies the application of the re-masking protocol
    pub fn verify_remask(&self, m: &Mask, c: &Mask, proof: &MaskProof) -> Result<()> {
        let h = self.pk.point();
        let gr = c.0 - m.0;
        let hr = c.1 - m.1;
        proof.verify(&mut Transcript::new(b"remask"), dlog_eq::Publics {
            a: &gr,
            b: &hr,
            g: &G.basepoint(),
            h: &h,
        })
    }
}

impl Vtmf {
    /// Obtains one share of a masking operation
    pub fn unmask_share(&self, c: &Mask) -> (SecretShare, SecretShareProof) {
        let x = &self.sk.exponent();

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

        (SecretShare(d), proof)
    }

    /// Verifies a secret share of a masking operation
    pub fn verify_unmask(
        &self,
        c: &Mask,
        pk_fp: &Fingerprint,
        d: &SecretShare,
        proof: &SecretShareProof,
    ) -> Result<()> {
        let pk = self.pki.get(pk_fp);
        let pk = match pk {
            None => {
                return Err(Error::BadProof);
            }
            Some(pk) => pk,
        };
        proof.verify(&mut Transcript::new(b"mask_share"), dlog_eq::Publics {
            a: &d.0,
            b: &pk.point(),
            g: &c.0,
            h: &G.basepoint(),
        })
    }

    /// Undoes part of a masking operation
    pub fn unmask(&self, c: &Mask, d: &SecretShare) -> Mask {
        Mask(c.0, c.1 - d.0)
    }

    /// Privately undoes a masking operation
    pub fn unmask_private(&self, c: &Mask) -> Mask {
        let d = self.unmask_share(&c).0;
        self.unmask(c, &d)
    }

    /// Undoes a non-secret masking operation
    pub fn unmask_open(&self, m: &Mask) -> RistrettoPoint {
        m.1
    }
}

impl Vtmf {
    /// Applies the mask-shuffle protocol for a given permutation
    pub fn mask_shuffle(&self, m: &Stack, pi: &Permutation) -> (Stack, Vec<Scalar>, ShuffleProof) {
        let mut rng = thread_rng();

        let h = self.pk.point();

        let r: Vec<_> = iter::repeat_with(|| Scalar::random(&mut rng))
            .take(m.len())
            .collect();

        let (mut rm, mut r): (Stack, Vec<_>) = m
            .iter()
            .zip(r.iter())
            .map(|(c, r)| {
                let c1 = G * r + c.0;
                let c2 = h * r + c.1;
                (Mask(c1, c2), r)
            })
            .unzip();
        pi.apply_to(&mut rm);
        pi.apply_to(&mut r);

        let proof = ShuffleProof::create(
            &mut Transcript::new(b"mask_shuffle"),
            secret_shuffle::Publics {
                h: &h,
                e0: m,
                e1: &rm,
            },
            secret_shuffle::Secrets { pi, r: &r },
        );
        (rm, r, proof)
    }

    /// Verifies the application of the mask-shuffling protocol
    pub fn verify_mask_shuffle(&self, m: &Stack, c: &Stack, proof: &ShuffleProof) -> Result<()> {
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
    /// Applies the mask-shift protocol for a given permutation
    pub fn mask_shift(&self, m: &Stack, k: usize) -> (Stack, Vec<Scalar>, ShiftProof) {
        let mut rng = thread_rng();

        let h = self.pk.point();

        let (rm, r) = self.do_shift(m, k, &mut rng);

        let proof = ShiftProof::create(
            &mut Transcript::new(b"mask_shift"),
            secret_rotation::Publics {
                h: &h,
                e0: m,
                e1: &rm,
            },
            secret_rotation::Secrets { k, r: &r },
        );
        (rm, r, proof)
    }

    /// Verifies the application of the mask-shifting protocol
    pub fn verify_mask_shift(&self, m: &Stack, c: &Stack, proof: &ShiftProof) -> Result<()> {
        proof.verify(
            &mut Transcript::new(b"mask_shift"),
            secret_rotation::Publics {
                h: &self.pk.point(),
                e0: m,
                e1: c,
            },
        )
    }

    fn do_shift<R: Rng + CryptoRng>(
        &self,
        m: &Stack,
        k: usize,
        rng: &mut R,
    ) -> (Stack, Vec<Scalar>) {
        let h = self.pk.point();

        let remask = |c: &Mask| {
            let r = Scalar::random(rng);

            let c1 = G * &r + c.0;
            let c2 = h * r + c.1;
            (Mask(c1, c2), r)
        };

        let (mut rm, mut r): (Stack, Vec<_>) = m.iter().map(remask).unzip();
        let pi = Permutation::shift(m.len(), k);
        pi.apply_to(&mut rm);
        pi.apply_to(&mut r);

        (rm, r)
    }
}

impl Vtmf {
    /// Applies a random mask
    pub fn mask_random<R: Rng + CryptoRng>(&self, rng: &mut R) -> Mask {
        let p = RistrettoPoint::random(rng);
        self.mask(&p).0
    }

    /// Undoes a random mask
    pub fn unmask_random(&self, m: &Mask) -> impl XofReader {
        let mut h = TranscriptHash::new(b"pbmx-random");
        m.append_to_transcript(&mut h, b"entropy");
        h.into_xof()
    }
}

impl Vtmf {
    /// Proves that multiple stacks have been reordered according to the same
    /// permutation
    pub fn prove_entanglement<'a, It1, It2, It3>(
        &self,
        m: It1,
        c: It2,
        pi: &Permutation,
        secrets: It3,
    ) -> EntanglementProof
    where
        It1: Iterator<Item = &'a Stack>,
        It2: Iterator<Item = &'a Stack>,
        It3: Iterator<Item = &'a [Scalar]>,
    {
        let h = self.pk.point();

        let m: Vec<_> = m.map(|s| &s[..]).collect();
        let c: Vec<_> = c.map(|s| &s[..]).collect();
        let r: Vec<_> = secrets.collect();
        entanglement::Proof::create(
            &mut Transcript::new(b"entanglement"),
            entanglement::Publics {
                h: &h,
                e0: &m,
                e1: &c,
            },
            entanglement::Secrets { pi, r: &r },
        )
    }

    /// Proves that multiple stacks have been reordered according to the same
    /// permutation
    pub fn verify_entanglement<'a, It1, It2>(
        &self,
        m: It1,
        c: It2,
        proof: &EntanglementProof,
    ) -> Result<()>
    where
        It1: Iterator<Item = &'a Stack>,
        It2: Iterator<Item = &'a Stack>,
    {
        let h = self.pk.point();

        let m: Vec<_> = m.map(|s| &s[..]).collect();
        let c: Vec<_> = c.map(|s| &s[..]).collect();
        proof.verify(
            &mut Transcript::new(b"entanglement"),
            entanglement::Publics {
                h: &h,
                e0: &m,
                e1: &c,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Mask, Stack, Vtmf};
    use crate::{
        crypto::{
            keys::PrivateKey,
            map,
            perm::{Permutation, Shuffles},
        },
        Error,
    };
    use digest::XofReader;
    use rand::{thread_rng, Rng};

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
        vtmf0.add_key(pk1);
        vtmf1.add_key(pk0);

        let x = rng.gen_range(0..16);
        let p = map::to_curve(x);
        let (mask, _, proof) = vtmf0.mask(&p);
        let verified = vtmf1.verify_mask(&p, &mask, &proof);
        assert_eq!(verified, Ok(()));
        let p = map::to_curve(x + 1);
        let invalid = vtmf1.verify_mask(&p, &mask, &proof);
        assert_eq!(invalid, Err(Error::BadProof));

        let (remask, _, proof) = vtmf0.remask(&mask);
        let verified = vtmf1.verify_remask(&mask, &remask, &proof);
        assert_eq!(verified, Ok(()));
        let (remask, ..) = vtmf0.remask(&remask);
        let invalid = vtmf1.verify_remask(&mask, &remask, &proof);
        assert_eq!(invalid, Err(Error::BadProof));

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let verified = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert_eq!(verified, Ok(()));
        let invalid = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof0);
        assert_eq!(invalid, Err(Error::BadProof));
        let mask0 = vtmf0.unmask(&mask, &d1);
        let mask0 = vtmf0.unmask_private(&mask0);
        let r = vtmf0.unmask_open(&mask0);
        let r = map::from_curve(&r);
        assert_eq!(r, x);

        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let invalid = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof1);
        assert_eq!(invalid, Err(Error::BadProof));
        let mask1 = vtmf1.unmask(&mask, &d0);
        let mask1 = vtmf1.unmask_private(&mask1);
        let r = vtmf1.unmask_open(&mask1);
        let r = map::from_curve(&r);
        assert_eq!(r, x);
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
        vtmf0.add_key(pk1);
        vtmf1.add_key(pk0);

        let x = rng.gen_range(0..16);
        let p = map::to_curve(x);
        let mask = Mask::open(p);

        let open = vtmf1.unmask_open(&mask);
        let open = map::from_curve(&open);
        assert_eq!(open, x);

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let verified = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert_eq!(verified, Ok(()));
        let mask0 = vtmf0.unmask(&mask, &d1);
        let mask0 = vtmf0.unmask_private(&mask0);
        let r = vtmf0.unmask_open(&mask0);
        let r = map::from_curve(&r);
        assert_eq!(r, x);

        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let mask1 = vtmf1.unmask(&mask, &d0);
        let mask1 = vtmf1.unmask_private(&mask1);
        let r = vtmf1.unmask_open(&mask1);
        let r = map::from_curve(&r);
        assert_eq!(r, x);
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
        vtmf0.add_key(pk1);
        vtmf1.add_key(pk0);

        let m: Stack = (0u64..8)
            .map(map::to_curve)
            .map(|p| vtmf0.mask(&p).0)
            .collect();
        let pi = thread_rng().sample(&Shuffles(m.len()));
        let (shuffle, _, proof) = vtmf0.mask_shuffle(&m, &pi);
        let verified = vtmf1.verify_mask_shuffle(&m, &shuffle, &proof);
        assert_eq!(verified, Ok(()));
        let mut m2 = m.clone();
        m2[0] = vtmf0.mask(&map::to_curve(8)).0;
        let invalid = vtmf1.verify_mask_shuffle(&m2, &shuffle, &proof);
        assert_eq!(invalid, Err(Error::BadProof));

        let open: Vec<_> = shuffle
            .iter()
            .map(|m| {
                let (d0, proof0) = vtmf0.unmask_share(m);
                let verified = vtmf1.verify_unmask(m, &fp0, &d0, &proof0);
                assert_eq!(verified, Ok(()));
                let mask1 = vtmf1.unmask(m, &d0);
                let mask1 = vtmf1.unmask_private(&mask1);
                let r = vtmf1.unmask_open(&mask1);
                map::from_curve(&r)
            })
            .collect();
        let mut expected: Vec<_> = (0u64..8).collect();
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
        vtmf0.add_key(pk1);
        vtmf1.add_key(pk0);

        let m: Stack = (0u64..8)
            .map(map::to_curve)
            .map(|p| vtmf0.mask(&p).0)
            .collect();
        let k = thread_rng().gen_range(0..8);
        let (shift, _, proof) = vtmf0.mask_shift(&m, k);
        let verified = vtmf1.verify_mask_shift(&m, &shift, &proof);
        assert_eq!(verified, Ok(()));
        let mut m2 = m.clone();
        m2.swap(0, 1);
        let invalid = vtmf1.verify_mask_shift(&m2, &shift, &proof);
        assert_eq!(invalid, Err(Error::BadProof));

        let open: Vec<_> = shift
            .iter()
            .map(|m| {
                let (d0, proof0) = vtmf0.unmask_share(m);
                let verified = vtmf1.verify_unmask(m, &fp0, &d0, &proof0);
                assert_eq!(verified, Ok(()));
                let mask1 = vtmf1.unmask(m, &d0);
                let mask1 = vtmf1.unmask_private(&mask1);
                let r = vtmf1.unmask_open(&mask1);
                map::from_curve(&r)
            })
            .collect();
        let mut expected: Vec<_> = (0u64..8).collect();
        let pi = Permutation::shift(8, k);
        pi.apply_to(&mut expected);
        assert_eq!(open, expected);
    }

    #[test]
    fn vtmf_random_masking_works() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        let fp0 = pk0.fingerprint();
        let fp1 = pk1.fingerprint();
        vtmf0.add_key(pk1);
        vtmf1.add_key(pk0);

        let mask0 = vtmf0.mask_random(&mut rng);
        let mask1 = vtmf1.mask_random(&mut rng);
        let mask = Mask(mask0.0 + mask1.0, mask0.1 + mask1.1);

        let (d0, proof0) = vtmf0.unmask_share(&mask);
        let (d1, proof1) = vtmf1.unmask_share(&mask);

        let verified = vtmf0.verify_unmask(&mask, &fp1, &d1, &proof1);
        assert_eq!(verified, Ok(()));
        let mask0 = vtmf0.unmask(&mask, &d1);
        let mask0 = vtmf0.unmask_private(&mask0);
        let mut xof0 = vtmf0.unmask_random(&mask0);

        let verified = vtmf1.verify_unmask(&mask, &fp0, &d0, &proof0);
        assert_eq!(verified, Ok(()));
        let mask1 = vtmf1.unmask(&mask, &d0);
        let mask1 = vtmf1.unmask_private(&mask1);
        let mut xof1 = vtmf1.unmask_random(&mask1);

        let mut buf0 = [0u8; 64].to_vec();
        let mut buf1 = [0u8; 64].to_vec();
        for _ in 0..1024 {
            xof0.read(&mut buf0);
            xof1.read(&mut buf1);
            assert_eq!(buf0, buf1);
        }
    }

    #[test]
    fn vtmf_entangled_mask_shuffling_works() {
        let mut rng = thread_rng();
        let sk0 = PrivateKey::random(&mut rng);
        let sk1 = PrivateKey::random(&mut rng);
        let pk0 = sk0.public_key();
        let pk1 = sk1.public_key();

        let mut vtmf0 = Vtmf::new(sk0);
        let mut vtmf1 = Vtmf::new(sk1);
        vtmf0.add_key(pk1);
        vtmf1.add_key(pk0);

        let m0: Stack = (0u64..8)
            .map(map::to_curve)
            .map(|p| vtmf0.mask(&p).0)
            .collect();
        let m1: Stack = (8u64..16)
            .map(map::to_curve)
            .map(|p| vtmf0.mask(&p).0)
            .collect();
        let m2: Stack = (16u64..24)
            .map(map::to_curve)
            .map(|p| vtmf0.mask(&p).0)
            .collect();

        let pi = rng.sample(&Shuffles(m0.len()));
        let m = [m0, m1, m2];
        let (shuffles, secrets): (Vec<_>, Vec<_>) = m
            .iter()
            .map(|m| {
                let (shuffle, secrets, _) = vtmf0.mask_shuffle(m, &pi);
                (shuffle, secrets)
            })
            .unzip();

        let proof = vtmf0.prove_entanglement(
            m.iter(),
            shuffles.iter(),
            &pi,
            secrets.iter().map(|s| &s[..]),
        );
        let verified = vtmf1.verify_entanglement(m.iter(), shuffles.iter(), &proof);
        assert_eq!(verified, Ok(()));
        let mut bad_shuffles = shuffles;
        let pi2 = rng.sample(&Shuffles(m[1].len()));
        bad_shuffles[1] = vtmf0.mask_shuffle(&m[1], &pi2).0;
        let invalid = vtmf1.verify_entanglement(m.iter(), bad_shuffles.iter(), &proof);
        assert_eq!(invalid, Err(Error::BadProof));
    }
}
