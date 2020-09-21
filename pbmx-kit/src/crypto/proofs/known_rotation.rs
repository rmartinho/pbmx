//! Rotation of known content argument

// [HSSV09] Sebastiaan de Hoogh, Berry Schoenmakers, Boris Skoric, and Jose
// Villegas:              'Verifiable Rotation of Homomorphic Encryptions',
//              Public Key Cryptography 2009, LNCS 5443, pp. 393--410, Springer
// 2009.

use super::{random_scalars, TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    crypto::{
        commit::Pedersen,
        hash::{Transcribe, TranscriptAppend},
        perm::Permutation,
    },
    proto,
    random::thread_rng,
    serde::{points_from_proto, points_to_proto, scalars_from_proto, scalars_to_proto, Proto},
    Error, Result,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    f: Vec<RistrettoPoint>,
    l: Vec<Scalar>,
    t: Vec<Scalar>,
}

impl Proto for Proof {
    type Message = proto::KnownRotationProof;

    fn to_proto(&self) -> Result<proto::KnownRotationProof> {
        Ok(proto::KnownRotationProof {
            f: points_to_proto(&self.f)?,
            l: scalars_to_proto(&self.l)?,
            t: scalars_to_proto(&self.t)?,
        })
    }

    fn from_proto(m: &proto::KnownRotationProof) -> Result<Self> {
        Ok(Proof {
            f: points_from_proto(&m.f)?,
            l: scalars_from_proto(&m.l)?,
            t: scalars_from_proto(&m.t)?,
        })
    }
}

impl Transcribe for Proof {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        b"known-rotation-proof".append_to_transcript(t, label);
        self.f.append_to_transcript(t, b"f");
        self.l.append_to_transcript(t, b"l");
        self.t.append_to_transcript(t, b"t");
    }
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

        transcript.commit(b"com", publics.com);
        transcript.commit(b"m", publics.m);
        transcript.commit(b"c", publics.c);

        let mut rng = transcript
            .build_rng()
            .rekey(b"k", &secrets.k)
            .rekey(b"r", secrets.r)
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

        let b: Vec<Scalar> = transcript.challenge_sized(b"b", n);
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
        transcript.commit(b"f", &f);

        let lambda: Scalar = transcript.challenge(b"lambda");
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
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<()> {
        transcript.domain_sep(b"known_rotation");

        transcript.commit(b"com", publics.com);
        transcript.commit(b"m", publics.m);
        transcript.commit(b"c", publics.c);

        let n = publics.m.len();

        let b: Vec<Scalar> = transcript.challenge_sized(b"b", n);
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

        transcript.commit(b"f", &self.f);

        let lambda: Scalar = transcript.challenge(b"lambda");
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
            Err(Error::BadProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::random_scalars, Proof, Publics, Secrets};
    use crate::{
        crypto::{commit::Pedersen, perm::Permutation},
        Error,
    };
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use rand::{thread_rng, Rng};

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let m = &random_scalars(8, &mut rng);
        let mut mp = m.clone();
        let k = rng.gen_range(0, 8);
        let pi = Permutation::shift(8, k);
        pi.apply_to(&mut mp);

        let com = &Pedersen::random(1, &mut rng);
        let (c, r): (Vec<_>, Vec<_>) = mp.iter().map(|m| com.commit_to(&[*m], &mut rng)).unzip();
        let publics = Publics { com, m, c: &c };
        let secrets = Secrets { k, r: &r };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.t[0] += Scalar::one();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(Error::BadProof));
    }
}
