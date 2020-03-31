//! Rotation of known content argument

// [HSSV09] Sebastiaan de Hoogh, Berry Schoenmakers, Boris Skoric, and Jose
// Villegas:              'Verifiable Rotation of Homomorphic Encryptions',
//              Public Key Cryptography 2009, LNCS 5443, pp. 393--410, Springer
// 2009.

use super::{random_scalars, TranscriptProtocol, TranscriptRngProtocol};
use crate::crypto::{commit::Pedersen, perm::Permutation};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    #[serde(with = "crate::serde::vec_point")]
    f: Vec<RistrettoPoint>,
    #[serde(with = "crate::serde::vec_scalar")]
    l: Vec<Scalar>,
    #[serde(with = "crate::serde::vec_scalar")]
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
    /// Generates a non-interactive rotation of known content argument
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
        let mut l = random_scalars(n, &mut rng);
        l[secrets.k] = Scalar::zero();
        let mut t = random_scalars(n, &mut rng);
        t[secrets.k] = Scalar::zero();

        let b = transcript.challenge_scalars(b"b", n);
        let y: Vec<_> = (0..n)
            .map(|i| {
                (0..n)
                    .map(|j| publics.m[(n + j - i) % n] * b[j])
                    .sum::<Scalar>()
            })
            .collect();
        let g = publics
            .c
            .iter()
            .zip(b.iter())
            .map(|(c, b)| c * b)
            .sum::<RistrettoPoint>();

        let com_u = publics.com.commit_by(&[Scalar::zero()], &u);
        let f: Vec<_> = l
            .iter()
            .zip(t.iter())
            .zip(y.iter())
            .enumerate()
            .map(|(i, ((l, t), y))| {
                let com_i = publics.com.commit_by(&[l * y], t) + g * -l;
                RistrettoPoint::conditional_select(&com_i, &com_u, i.ct_eq(&secrets.k))
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

    /// Verifies a non-interactive rotation of known content argument
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
    use super::{super::random_scalars, Proof, Publics, Secrets};
    use crate::crypto::{commit::Pedersen, perm::Permutation};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::{thread_rng, Rng};

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let h = &RistrettoPoint::random(&mut rng);

        let m = &random_scalars(8, &mut rng);
        let mut mp = m.clone();
        let k = rng.gen_range(0, 8);
        let pi = Permutation::shift(8, k);
        pi.apply_to(&mut mp);

        let com = &Pedersen::random(*h, 1, &mut rng);
        let (c, r): (Vec<_>, Vec<_>) = mp.iter().map(|m| com.commit_to(&[*m], &mut rng)).unzip();
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
