//! Shuffle of known content argument

// [Gr05] Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
//          Cryptology ePrint Archive, Report 2005/246, 2005.

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    crypto::{commit::Pedersen, hash::TranscriptHashable, perm::Permutation},
    proto,
    random::thread_rng,
    serde::{
        point_from_proto, point_to_proto, scalar_from_proto, scalar_to_proto, scalars_from_proto,
        scalars_to_proto, Proto,
    },
    Error, Result,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use std::iter;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    cd: RistrettoPoint,
    cdd: RistrettoPoint,
    cda: RistrettoPoint,
    f: Vec<Scalar>,
    z: Scalar,
    fd: Vec<Scalar>,
    zd: Scalar,
}

impl Proto for Proof {
    type Message = proto::KnownShuffleProof;

    fn to_proto(&self) -> Result<proto::KnownShuffleProof> {
        Ok(proto::KnownShuffleProof {
            cd: point_to_proto(&self.cd)?,
            cdd: point_to_proto(&self.cdd)?,
            cda: point_to_proto(&self.cda)?,
            f: scalars_to_proto(&self.f)?,
            z: scalar_to_proto(&self.z)?,
            fd: scalars_to_proto(&self.fd)?,
            zd: scalar_to_proto(&self.zd)?,
        })
    }

    fn from_proto(m: &proto::KnownShuffleProof) -> Result<Self> {
        Ok(Proof {
            cd: point_from_proto(&m.cd)?,
            cdd: point_from_proto(&m.cdd)?,
            cda: point_from_proto(&m.cda)?,
            f: scalars_from_proto(&m.f)?,
            z: scalar_from_proto(&m.z)?,
            fd: scalars_from_proto(&m.fd)?,
            zd: scalar_from_proto(&m.zd)?,
        })
    }
}

impl TranscriptHashable for Proof {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        b"known-shuffle-proof".append_to_transcript(t, label);
        self.cd.append_to_transcript(t, b"cd");
        self.cdd.append_to_transcript(t, b"cdd");
        self.cda.append_to_transcript(t, b"cda");
        self.f.append_to_transcript(t, b"f");
        self.z.append_to_transcript(t, b"z");
        self.fd.append_to_transcript(t, b"fd");
        self.zd.append_to_transcript(t, b"zd");
    }
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Commitment scheme
    pub com: &'a Pedersen,
    /// Commit to a shuffle
    pub c: &'a RistrettoPoint,
    /// Domain
    pub m: &'a [Scalar],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Permutation
    pub pi: &'a Permutation,
    /// Blinding factor
    pub r: &'a Scalar,
}

impl Proof {
    /// Generates a non-interactive shuffle of known content argument
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"known_shuffle");

        transcript.commit_pedersen(b"com", publics.com);
        transcript.commit_point(b"c", publics.c);
        transcript.commit_scalars(b"m", publics.m);

        let rekey_rng = |t: &Transcript| {
            t.build_rng()
                .commit_permutation(b"pi", secrets.pi)
                .commit_scalar(b"r", secrets.r)
                .finalize(&mut thread_rng())
        };
        let mut rng = rekey_rng(&transcript);

        let n = publics.m.len();

        let d: Vec<_> = iter::repeat_with(|| Scalar::random(&mut rng))
            .take(n)
            .collect();

        let mut delta = Vec::with_capacity(n);
        delta.push(d[0]);
        delta.extend(iter::repeat_with(|| Scalar::random(&mut rng)).take(n - 2));
        delta.push(Scalar::zero());

        let x = transcript.challenge_scalar(b"x");
        let a: Vec<_> = (1..=n)
            .map(|i| {
                secrets
                    .pi
                    .iter()
                    .take(i)
                    .map(|&p| publics.m[p] - x)
                    .product::<Scalar>()
            })
            .collect();

        let mut rng = rekey_rng(&transcript);

        let (cd, rd) = publics.com.commit_to(&d, &mut rng);
        transcript.commit_point(b"cd", &cd);

        let mut rng = rekey_rng(&transcript);

        let mut dd: Vec<_> = (1..n).map(|i| (-delta[i - 1]) * d[i]).collect();
        dd.push(Scalar::zero());
        let (cdd, rdd) = publics.com.commit_to(&dd, &mut rng);
        transcript.commit_point(b"cdd", &cdd);

        let mut rng = rekey_rng(&transcript);

        let mut da: Vec<_> = (1..n)
            .map(|i| delta[i] - (publics.m[secrets.pi[i]] - x) * delta[i - 1] - a[i - 1] * d[i])
            .collect();
        da.push(Scalar::zero());
        let (cda, rda) = publics.com.commit_to(&da, &mut rng);
        transcript.commit_point(b"cda", &cda);

        let e = transcript.challenge_scalar(b"e");
        let f: Vec<_> = secrets
            .pi
            .iter()
            .zip(d.iter())
            .map(|(&p, d)| e * publics.m[p] + d)
            .collect();
        let z = e * secrets.r + rd;

        let mut fd: Vec<_> = (1..n)
            .map(|i| {
                e * (delta[i] - (publics.m[secrets.pi[i]] - x) * delta[i - 1] - a[i - 1] * d[i])
                    - delta[i - 1] * d[i]
            })
            .collect();
        fd.push(Scalar::zero());
        let zd = e * rda + rdd;

        Self {
            cd,
            cdd,
            cda,
            f,
            z,
            fd,
            zd,
        }
    }

    /// Verifies a non-interactive shuffle of known content argument
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<()> {
        transcript.domain_sep(b"known_shuffle");

        transcript.commit_pedersen(b"com", publics.com);
        transcript.commit_point(b"c", publics.c);
        transcript.commit_scalars(b"m", publics.m);

        let x = transcript.challenge_scalar(b"x");

        transcript.commit_point(b"cd", &self.cd);
        transcript.commit_point(b"cdd", &self.cdd);
        transcript.commit_point(b"cda", &self.cda);

        let e = transcript.challenge_scalar(b"e");

        let n = publics.m.len();

        let cecd = publics.c * e + self.cd;
        publics.com.open(&cecd, &self.f, &self.z)?;
        let ceca = self.cda * e + self.cdd;
        publics.com.open(&ceca, &self.fd, &self.zd)?;

        let ex = e * x;
        let mut ff = self.f[0] - ex;
        for i in 1..n {
            ff = (ff * (self.f[i] - ex) + self.fd[i - 1]) * e.invert();
        }
        let prod = publics.m.iter().map(|m| m - x).product::<Scalar>();
        if ff == e * prod {
            Ok(())
        } else {
            Err(Error::BadProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Proof, Publics, Secrets};
    use crate::{
        crypto::{commit::Pedersen, perm::Shuffles},
        Error,
    };
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use rand::{thread_rng, Rng};
    use std::iter;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let m = &iter::repeat_with(|| Scalar::random(&mut rng))
            .take(8)
            .collect::<Vec<_>>();
        let mut mp = m.clone();
        let pi = &rng.sample(&Shuffles(8));
        pi.apply_to(&mut mp);

        let com = &Pedersen::random(8, &mut rng);
        let (c, r) = com.commit_to(&mp, &mut rng);
        let publics = Publics { com, c: &c, m };
        let secrets = Secrets { pi, r: &r };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.z += Scalar::one();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(Error::BadProof));
    }
}
