//! Verifiable secret shuffle of homomorphic encryptions

// [Gr05] Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
//          Cryptology ePrint Archive, Report 2005/246, 2005.

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    crypto::{
        commit::Pedersen,
        hash::{Transcribe, TranscriptAppend},
        perm::Permutation,
        proofs::known_shuffle,
        vtmf::Mask,
    },
    proto,
    random::thread_rng,
    serde::{
        point_from_proto, point_to_proto, scalar_from_proto, scalar_to_proto, scalars_from_proto,
        scalars_to_proto, Proto,
    },
    Error, Result,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use std::iter;

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    skc: known_shuffle::Proof,
    c: RistrettoPoint,
    cd: RistrettoPoint,
    ed: Mask,
    f: Vec<Scalar>,
    z: Scalar,
}

impl Proto for Proof {
    type Message = proto::ShuffleProof;

    fn to_proto(&self) -> Result<proto::ShuffleProof> {
        Ok(proto::ShuffleProof {
            skc: Some(self.skc.to_proto()?),
            c: point_to_proto(&self.c)?,
            cd: point_to_proto(&self.cd)?,
            ed: Some(self.ed.to_proto()?),
            f: scalars_to_proto(&self.f)?,
            z: scalar_to_proto(&self.z)?,
        })
    }

    fn from_proto(m: &proto::ShuffleProof) -> Result<Self> {
        Ok(Proof {
            skc: known_shuffle::Proof::from_proto(m.skc.as_ref().ok_or(Error::Decoding)?)?,
            c: point_from_proto(&m.c)?,
            cd: point_from_proto(&m.cd)?,
            ed: Mask::from_proto(m.ed.as_ref().ok_or(Error::Decoding)?)?,
            f: scalars_from_proto(&m.f)?,
            z: scalar_from_proto(&m.z)?,
        })
    }
}

impl Transcribe for Proof {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        b"secret-shuffle-proof".append_to_transcript(t, label);
        self.skc.append_to_transcript(t, b"skc");
        self.c.append_to_transcript(t, b"c");
        self.cd.append_to_transcript(t, b"cd");
        self.ed.append_to_transcript(t, b"ed");
        self.f.append_to_transcript(t, b"f");
        self.z.append_to_transcript(t, b"z");
    }
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// Original
    pub e0: &'a [Mask],
    /// Shuffled
    pub e1: &'a [Mask],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Permutation
    pub pi: &'a Permutation,
    /// Encryption blinding factors
    pub r: &'a [Scalar],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof of a secret shuffle
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"secret_shuffle");

        transcript.commit(b"h", publics.h);
        transcript.commit(b"e0", publics.e0);
        transcript.commit(b"e1", publics.e1);

        let n = publics.e0.len();
        let com: Pedersen = transcript.challenge_sized(b"com", n);

        let rekey_rng = |t: &Transcript| {
            t.build_rng()
                .rekey(b"pi", secrets.pi)
                .rekey(b"r", secrets.r)
                .finalize(&mut thread_rng())
        };
        let mut rng = rekey_rng(&transcript);

        let gh = Mask(G.basepoint(), *publics.h);

        let p2: Vec<_> = secrets
            .pi
            .iter()
            .map(|p| Scalar::from((p + 1) as u64))
            .collect();
        let (c, r) = com.commit_to(&p2, &mut rng);
        transcript.commit(b"c", &c);

        let mut rng = rekey_rng(&transcript);

        let d: Vec<_> = iter::repeat_with(|| Scalar::random(&mut rng))
            .map(|d| -d)
            .take(n)
            .collect();
        let (cd, rd) = com.commit_to(&d, &mut rng);
        transcript.commit(b"cd", &cd);

        let ed = gh * rd
            + d.iter()
                .zip(publics.e1.iter())
                .map(|(d, e)| e * d)
                .sum::<Mask>();
        transcript.commit(b"ed", &ed);

        let t: Vec<Scalar> = transcript.challenge_sized(b"t", n);

        let f: Vec<_> = secrets
            .pi
            .iter()
            .zip(d.iter())
            .map(|(p, d)| t[*p] - d)
            .collect();
        transcript.commit(b"f", &f);

        let z = secrets
            .pi
            .iter()
            .zip(secrets.r.iter())
            .map(|(p, r)| t[*p] * r)
            .sum::<Scalar>()
            + rd;
        transcript.commit(b"z", &z);

        let l: Scalar = transcript.challenge(b"l");

        let m: Vec<_> = (0..n)
            .map(|i| l * Scalar::from((i + 1) as u64) + t[i])
            .collect();
        let commit = c * l + cd + com.commit_by(&f, &Scalar::zero());
        let rho = l * r + rd;

        let skc = known_shuffle::Proof::create(
            transcript,
            known_shuffle::Publics {
                com: &com,
                c: &commit,
                m: &m,
            },
            known_shuffle::Secrets {
                pi: secrets.pi,
                r: &rho,
            },
        );

        Self {
            skc,
            c,
            cd,
            ed,
            f,
            z,
        }
    }

    /// Verifies a non-interactive zero-knowledge proof of a secret shuffle
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<()> {
        transcript.domain_sep(b"secret_shuffle");

        transcript.commit(b"h", publics.h);
        transcript.commit(b"e0", publics.e0);
        transcript.commit(b"e1", publics.e1);

        let n = publics.e0.len();
        let com: Pedersen = transcript.challenge_sized(b"com", n);

        let gh = Mask(G.basepoint(), *publics.h);

        transcript.commit(b"c", &self.c);
        transcript.commit(b"cd", &self.cd);
        transcript.commit(b"ed", &self.ed);

        let t: Vec<Scalar> = transcript.challenge_sized(b"t", n);

        transcript.commit(b"f", &self.f);
        transcript.commit(b"z", &self.z);

        let l: Scalar = transcript.challenge(b"l");

        let m: Vec<_> = (0..n)
            .map(|i| l * Scalar::from((i + 1) as u64) + t[i])
            .collect();
        let commit = self.c * l + self.cd + com.commit_by(&self.f, &Scalar::zero());

        self.skc.verify(transcript, known_shuffle::Publics {
            com: &com,
            c: &commit,
            m: &m,
        })?;

        let efed = self.ed
            + publics
                .e1
                .iter()
                .zip(self.f.iter())
                .map(|(e, f)| e * f)
                .sum::<Mask>();
        let etfd = efed
            + publics
                .e0
                .iter()
                .zip(t.iter())
                .map(|(e, t)| e * -t)
                .sum::<Mask>();

        let ez = gh * self.z;

        if etfd == ez {
            Ok(())
        } else {
            Err(Error::BadProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::random_scalars, Proof, Publics, Secrets, G};
    use crate::{
        crypto::{perm::Shuffles, vtmf::Mask},
        Error,
    };
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::{thread_rng, Rng};

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let h = &RistrettoPoint::random(&mut rng);
        let gh = Mask(G.basepoint(), *h);

        let m = &random_scalars(8, &mut rng);
        let e0: Vec<_> = m
            .into_iter()
            .map(|m| {
                let r = Scalar::random(&mut rng);
                gh * r + Mask::open(G * &m)
            })
            .collect();
        let (mut e1, mut r): (Vec<_>, Vec<_>) = e0
            .iter()
            .map(|e| {
                let r = Scalar::random(&mut rng);
                (gh * r + e, r)
            })
            .unzip();
        let pi = &rng.sample(&Shuffles(8));
        pi.apply_to(&mut e1);
        pi.apply_to(&mut r);

        let publics = Publics {
            h,
            e0: &e0,
            e1: &e1,
        };
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
