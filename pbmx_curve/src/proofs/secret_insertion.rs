//! Verifiable secret insertion of homomorphic encryptions

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    perm::Permutation,
    proofs::{dlog_eq_1of2, secret_rotation},
    vtmf::Mask,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::{thread_rng, Rng};
use subtle::ConditionallySelectable;

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    rot1: secret_rotation::Proof,
    s1: Vec<Mask>,
    rot2: secret_rotation::Proof,
    eq_top_bottom: dlog_eq_1of2::Proof,
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// Token
    pub c: &'a [Mask],
    /// Original
    pub s0: &'a [Mask],
    /// Inserted
    pub s2: &'a [Mask],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Position
    pub k: usize,
    /// Blinding factors for first shift
    pub r1: &'a [Scalar],
    /// Blinding factors for second shift
    pub r2: &'a [Scalar],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof of a shuffle of known
    /// content
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"secret_insert");

        transcript.commit_masks(b"c", publics.c);
        transcript.commit_masks(b"s0", publics.s0);
        transcript.commit_masks(b"s2", publics.s2);

        let mut rng = transcript
            .build_rng()
            .commit_index(b"k", secrets.k)
            .commit_scalars(b"r1", secrets.r1)
            .commit_scalars(b"r2", secrets.r2)
            .finalize(&mut thread_rng());

        let n = publics.s0.len();
        let n2 = publics.s2.len();
        let gh = Mask(G.basepoint(), *publics.h);

        let k = secrets.k % n;
        let mut s1 = publics.s0.to_vec();
        let p = Permutation::shift(s1.len(), k);
        p.apply_to(&mut s1);
        for (s, r) in s1.iter_mut().zip(secrets.r1.iter()) {
            *s += gh * r;
        }
        transcript.commit_masks(b"s1", &s1);

        let rot1 = secret_rotation::Proof::create(
            transcript,
            secret_rotation::Publics {
                h: publics.h,
                e0: publics.s0,
                e1: &s1,
            },
            secret_rotation::Secrets { k, r: secrets.r1 },
        );

        let mut s1c = s1.clone();
        s1c.extend_from_slice(publics.c);
        transcript.commit_masks(b"s1c", &s1c);

        let rot2 = secret_rotation::Proof::create(
            transcript,
            secret_rotation::Publics {
                h: publics.h,
                e0: &s1c,
                e1: publics.s2,
            },
            secret_rotation::Secrets {
                k: (n2 - secrets.k) % n2,
                r: secrets.r2,
            },
        );

        let mut ir1 = secrets.r1.to_vec();
        p.inverse().apply_to(&mut ir1);

        let coin_flip = rng.gen::<bool>() as u8;
        let on_top = (secrets.k != n) as u8;
        let in_middle = (secrets.k != n && secrets.k != 0) as u8;
        let is_first = u8::conditional_select(&on_top, &coin_flip, in_middle.into());

        let top_x = ir1[0] + secrets.r2[0];
        let bottom_x = ir1[n - 1] + secrets.r2[n2 - 1];

        let eq_top_bottom = dlog_eq_1of2::Proof::create(
            transcript,
            dlog_eq_1of2::Publics {
                a1: &(publics.s2[0].0 - publics.s0[0].0),
                b1: &(publics.s2[0].1 - publics.s0[0].1),
                a2: &(publics.s2[n2 - 1].0 - publics.s0[n - 1].0),
                b2: &(publics.s2[n2 - 1].1 - publics.s0[n - 1].1),
                g: &G.basepoint(),
                h: publics.h,
            },
            dlog_eq_1of2::Secrets {
                is_first: is_first == 1,
                x: &Scalar::conditional_select(&bottom_x, &top_x, (is_first as u8).into()),
            },
        );

        Self {
            rot1,
            s1,
            rot2,
            eq_top_bottom,
        }
    }

    /// Verifies a non-interactive zero-knowledge proof of a shuffle of known
    /// content
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"secret_insert");

        transcript.commit_masks(b"c", publics.c);
        transcript.commit_masks(b"s0", publics.s0);
        transcript.commit_masks(b"s2", publics.s2);
        transcript.commit_masks(b"s1", &self.s1);

        let n = publics.s0.len();
        let n2 = publics.s2.len();

        self.rot1.verify(transcript, secret_rotation::Publics {
            h: publics.h,
            e0: publics.s0,
            e1: &self.s1,
        })?;

        let mut s1c = self.s1.clone();
        s1c.extend_from_slice(publics.c);
        transcript.commit_masks(b"s1c", &s1c);

        self.rot2.verify(transcript, secret_rotation::Publics {
            h: publics.h,
            e0: &s1c,
            e1: publics.s2,
        })?;

        self.eq_top_bottom
            .verify(transcript, dlog_eq_1of2::Publics {
                a1: &(publics.s2[0].0 - publics.s0[0].0),
                b1: &(publics.s2[0].1 - publics.s0[0].1),
                a2: &(publics.s2[n2 - 1].0 - publics.s0[n - 1].0),
                b2: &(publics.s2[n2 - 1].1 - publics.s0[n - 1].1),
                g: &G.basepoint(),
                h: publics.h,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::random_scalars, Proof, Publics, Secrets, G};
    use crate::{perm::Permutation, vtmf::Mask};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::{thread_rng, Rng};
    use std::iter;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let h = &RistrettoPoint::random(&mut rng);
        let gh = Mask(G.basepoint(), *h);

        let c: Vec<_> = iter::repeat_with(|| Mask::open(RistrettoPoint::random(&mut rng)))
            .take(3)
            .collect();

        let m = &random_scalars(8, &mut rng);
        let s0: Vec<_> = m
            .into_iter()
            .map(|m| {
                let r = Scalar::random(&mut rng);
                gh * r + Mask::open(G * &m)
            })
            .collect();
        let (mut s1, mut r1): (Vec<_>, Vec<_>) = s0
            .iter()
            .map(|s| {
                let r = Scalar::random(&mut rng);
                (gh * r + s, r)
            })
            .unzip();
        let k = rng.gen_range(0, 9);
        let p1 = Permutation::shift(8, k);
        p1.apply_to(&mut s1);
        p1.apply_to(&mut r1);

        let mut s1c = s1.clone();
        s1c.extend_from_slice(&c);
        let (mut s2, mut r2): (Vec<_>, Vec<_>) = s1c
            .iter()
            .map(|s| {
                let r = Scalar::random(&mut rng);
                (gh * r + s, r)
            })
            .unzip();
        let p2 = Permutation::shift(11, (11 - k) % 11);
        p2.apply_to(&mut s2);
        p2.apply_to(&mut r2);

        let publics = Publics {
            h,
            c: &c,
            s0: &s0,
            s2: &s2,
        };
        let secrets = Secrets {
            k,
            r1: &r1,
            r2: &r2,
        };

        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);
        proof.s1.pop();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
