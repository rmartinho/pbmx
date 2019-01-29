//! Hoogh et al's verifiable rotation of known content

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{commit::Pedersen, perm::Permutation};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;
use std::iter;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    f: Vec<RistrettoPoint>,
    l: Vec<Scalar>,
    t: Vec<Scalar>,
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Commitment scheme
    pub com: &'a Pedersen,
    /// Source
    pub m: &'a [Scalar],
    /// Commits
    pub c: &'a [RistrettoPoint],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Shift
    pub k: usize,
    /// Commit blinding factors
    pub r: &'a [Scalar],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof of a shuffle of known
    /// content
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"known_rotation");

        transcript.commit_pedersen(b"com", publics.com);
        transcript.commit_scalars(b"m", publics.m);
        transcript.commit_points(b"c", publics.c);

        let mut rng = transcript
            .build_rng()
            .commit_index(b"k", secrets.k)
            .commit_scalars(b"r", secrets.r)
            .finalize(&mut thread_rng());

        let n = publics.m.len();

        let shift = Permutation::shift(n, secrets.k);
        let mut sm = publics.m.to_vec();
        shift.apply_to(&mut sm);

        let u = Scalar::random(&mut rng);
        let mut l: Vec<_> = iter::repeat_with(|| Scalar::random(&mut rng))
            .take(n)
            .collect();
        l[secrets.k] = Scalar::zero();
        let mut t: Vec<_> = iter::repeat_with(|| Scalar::random(&mut rng))
            .take(n)
            .collect();
        t[secrets.k] = Scalar::zero();

        let b = transcript.challenge_scalars(b"b", n);
        let y: Vec<_> = (0..n)
            .map(|k| {
                (0..n)
                    .map(|j| publics.m[(n + j - k) % n] * b[j])
                    .sum::<Scalar>()
            })
            .collect();
        let g = publics
            .c
            .iter()
            .zip(b.iter())
            .map(|(c, b)| c * b)
            .sum::<RistrettoPoint>();

        let f: Vec<_> = l
            .iter()
            .zip(t.iter())
            .zip(y.iter())
            .enumerate()
            .map(|(i, ((l, t), y))| {
                if i == secrets.k {
                    publics.com.commit_by(&[Scalar::zero()], &u)
                } else {
                    publics.com.commit_by(&[l * y], t) + g * -l
                }
            })
            .collect();
        transcript.commit_points(b"f", &f);

        let lambda = transcript.challenge_scalar(b"lambda");
        l[secrets.k] = lambda - l.iter().sum::<Scalar>();
        let br = b
            .iter()
            .zip(secrets.r.iter())
            .map(|(b, r)| b * r)
            .sum::<Scalar>();
        t[secrets.k] = u + l[secrets.k] * br;
        Self { f, l, t }
    }

    /// Verifies a non-interactive zero-knowledge proof of a shuffle of known
    /// content
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"known_rotation");

        transcript.commit_pedersen(b"com", publics.com);
        transcript.commit_scalars(b"m", publics.m);
        transcript.commit_points(b"c", publics.c);

        let n = publics.m.len();

        let b = transcript.challenge_scalars(b"b", n);
        let y: Vec<_> = (0..n)
            .map(|k| {
                (0..n)
                    .map(|j| publics.m[(n + j - k) % n] * b[j])
                    .sum::<Scalar>()
            })
            .collect();
        let g = publics
            .c
            .iter()
            .zip(b.iter())
            .map(|(c, b)| c * b)
            .sum::<RistrettoPoint>();

        transcript.commit_points(b"f", &self.f);

        let lambda = transcript.challenge_scalar(b"lambda");
        let fgl: Vec<_> = self
            .l
            .iter()
            .zip(self.f.iter())
            .zip(y.iter())
            .map(|((l, f), y)| {
                let gy = publics.com.commit_by(&[*y], &Scalar::zero());
                f + (g - gy) * l
            })
            .collect();

        let ht: Vec<_> = self
            .t
            .iter()
            .map(|t| publics.com.commit_by(&[Scalar::zero()], t))
            .collect();

        let l_sum = self.l.iter().sum::<Scalar>();
        if lambda == l_sum && ht == fgl {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Proof, Publics, Secrets};
    use crate::{
        commit::Pedersen,
        perm::{Permutation, Shuffles},
    };
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::{thread_rng, Rng};
    use std::iter;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let g = &RistrettoPoint::random(&mut rng);
        let h = &RistrettoPoint::random(&mut rng);

        let m = &iter::repeat_with(|| Scalar::random(&mut rng))
            .take(8)
            .collect::<Vec<_>>();
        let mut mp = m.clone();
        let k = rng.gen_range(0, 8);
        let pi = Permutation::shift(8, k);
        pi.apply_to(&mut mp);

        let com = &Pedersen::new(*h, 1, &mut rng);
        let (c, r): (Vec<_>, Vec<_>) = mp.iter().map(|m| com.commit_to(&[*m])).unzip();
        let publics = Publics { com, m, c: &c };
        let secrets = Secrets { k, r: &r };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.t[0] += Scalar::one();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
