//! Proof of entanglement of stacks

use super::TranscriptProtocol;
use crate::crypto::{perm::Permutation, proofs::secret_shuffle, vtmf::Mask};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use std::ops::{Add, Mul};

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    tangles: Vec<secret_shuffle::Proof>,
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// Original
    pub e0: &'a [&'a [Mask]],
    /// Shuffled
    pub e1: &'a [&'a [Mask]],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Permutation
    pub pi: &'a Permutation,
    /// Encryption blinding factors
    pub r: &'a [&'a [Scalar]],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof of an entangled shuffle
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"entanglement");

        let e0_pairs = publics.e0.iter().zip(publics.e0.iter().skip(1));
        let e1_pairs = publics.e1.iter().zip(publics.e1.iter().skip(1));
        let r_pairs = secrets.r.iter().zip(secrets.r.iter().skip(1));
        let tangles = e0_pairs
            .zip(e1_pairs)
            .zip(r_pairs)
            .map(|(((a0, b0), (a1, b1)), (ra, rb))| {
                let e0 = entangle(a0, b0);
                let e1 = entangle(a1, b1);
                let r = entangle(&ra, &rb);
                secret_shuffle::Proof::create(
                    transcript,
                    secret_shuffle::Publics {
                        h: publics.h,
                        e0: &e0,
                        e1: &e1,
                    },
                    secret_shuffle::Secrets {
                        pi: secrets.pi,
                        r: &r,
                    },
                )
            })
            .collect();
        Self { tangles }
    }

    /// Verifies a non-interactive zero-knowledge proof of an entangled shuffle
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"entanglement");

        let entangled_e0 = publics
            .e0
            .iter()
            .zip(publics.e0.iter().skip(1))
            .map(|(a, b)| entangle(a, b));
        let entangled_e1 = publics
            .e1
            .iter()
            .zip(publics.e1.iter().skip(1))
            .map(|(a, b)| entangle(a, b));
        entangled_e0
            .zip(entangled_e1)
            .zip(self.tangles.iter())
            .map(|((e0, e1), p)| {
                p.verify(transcript, secret_shuffle::Publics {
                    h: publics.h,
                    e0: &e0,
                    e1: &e1,
                })
            })
            .fold(Ok(()), Result::and)
    }
}

const TWO64_BYTES: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn entangle<T>(a: &[T], b: &[T]) -> Vec<T>
where
    for<'a> &'a T: Mul<Scalar, Output = T>,
    for<'a> T: Add<&'a T, Output = T>,
{
    let two64 = Scalar::from_bytes_mod_order(TWO64_BYTES);
    a.iter().zip(b.iter()).map(|(a, b)| a * two64 + b).collect()
}

#[cfg(test)]
mod tests {
    use super::{super::random_scalars, Proof, Publics, Secrets};
    use crate::crypto::{perm::Shuffles, vtmf::Mask};
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_TABLE,
        ristretto::{RistrettoBasepointTable, RistrettoPoint},
        scalar::Scalar,
    };
    use merlin::Transcript;
    use rand::{thread_rng, Rng};

    const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let h = &RistrettoPoint::random(&mut rng);
        let gh = Mask(G.basepoint(), *h);

        let m = &[
            random_scalars(8, &mut rng),
            random_scalars(8, &mut rng),
            random_scalars(8, &mut rng),
        ];
        let e0: Vec<Vec<_>> = m
            .into_iter()
            .map(|m| {
                m.into_iter()
                    .map(|m| {
                        let r = Scalar::random(&mut rng);
                        gh * r + Mask::open(G * &m)
                    })
                    .collect()
            })
            .collect();
        let (mut e1, mut r): (Vec<_>, Vec<_>) = e0
            .iter()
            .map(|e| {
                let (e1, r): (Vec<_>, Vec<_>) = e
                    .iter()
                    .map(|e| {
                        let r = Scalar::random(&mut rng);
                        (gh * r + e, r)
                    })
                    .unzip();
                (e1, r)
            })
            .unzip();
        let pi = &rng.sample(&Shuffles(8));
        e1.iter_mut().for_each(|e1| pi.apply_to(e1));
        r.iter_mut().for_each(|r| pi.apply_to(r));

        let publics = Publics {
            h,
            e0: &[&e0[0], &e0[1], &e0[2]],
            e1: &[&e1[0], &e1[1], &e1[2]],
        };
        let secrets = Secrets {
            pi,
            r: &[&r[0], &r[1], &r[2]],
        };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.tangles[0] = proof.tangles[1].clone();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
