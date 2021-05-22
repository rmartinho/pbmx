//! Verifiable rotation of homomorphic encryptions

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
        proofs::known_rotation,
        vtmf::Mask,
    },
    proto,
    random::thread_rng,
    serde::{
        points_from_proto, points_to_proto, scalar_from_proto, scalar_to_proto, scalars_from_proto,
        scalars_to_proto, vec_from_proto, vec_to_proto, Proto,
    },
    Error, Result,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    rkc: known_rotation::Proof,
    h: Vec<RistrettoPoint>,
    z: Vec<Mask>,
    v: Scalar,
    f: Vec<RistrettoPoint>,
    ff: Vec<Mask>,
    tau: Vec<Scalar>,
    rho: Vec<Scalar>,
    mu: Vec<Scalar>,
}

impl Proto for Proof {
    type Message = proto::RotationProof;

    fn to_proto(&self) -> Result<proto::RotationProof> {
        Ok(proto::RotationProof {
            rkc: Some(self.rkc.to_proto()?),
            h: points_to_proto(&self.h)?,
            z: vec_to_proto(&self.z)?,
            v: scalar_to_proto(&self.v)?,
            f: points_to_proto(&self.f)?,
            ff: vec_to_proto(&self.ff)?,
            tau: scalars_to_proto(&self.tau)?,
            rho: scalars_to_proto(&self.rho)?,
            mu: scalars_to_proto(&self.mu)?,
        })
    }

    fn from_proto(m: &proto::RotationProof) -> Result<Self> {
        Ok(Proof {
            rkc: known_rotation::Proof::from_proto(m.rkc.as_ref().ok_or(Error::Decoding)?)?,
            h: points_from_proto(&m.h)?,
            z: vec_from_proto(&m.z)?,
            v: scalar_from_proto(&m.v)?,
            f: points_from_proto(&m.f)?,
            ff: vec_from_proto(&m.ff)?,
            tau: scalars_from_proto(&m.tau)?,
            rho: scalars_from_proto(&m.rho)?,
            mu: scalars_from_proto(&m.mu)?,
        })
    }
}

impl Transcribe for Proof {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        b"secret-rotation-proof".append_to_transcript(t, label);
        self.rkc.append_to_transcript(t, b"rkc");
        self.h.append_to_transcript(t, b"h");
        self.z.append_to_transcript(t, b"z");
        self.v.append_to_transcript(t, b"v");
        self.f.append_to_transcript(t, b"f");
        self.ff.append_to_transcript(t, b"ff");
        self.tau.append_to_transcript(t, b"tau");
        self.rho.append_to_transcript(t, b"rho");
        self.mu.append_to_transcript(t, b"mu");
    }
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// Original
    pub e0: &'a [Mask],
    /// Shifted
    pub e1: &'a [Mask],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Shift factor
    pub k: usize,
    /// Encryption blinding factors
    pub r: &'a [Scalar],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof of a shuffle of known
    /// content
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"secret_rotation");

        transcript.commit(b"h", publics.h);
        transcript.commit(b"e0", publics.e0);
        transcript.commit(b"e1", publics.e1);

        let com: Pedersen = transcript.challenge_sized(b"com", 1);

        let rekey_rng = |t: &Transcript| {
            t.build_rng()
                .rekey(b"k", &secrets.k)
                .rekey(b"r", secrets.r)
                .finalize(&mut thread_rng())
        };

        let n = publics.e0.len();
        let gh = Mask(G.basepoint(), *publics.h);

        let a: Vec<Scalar> = transcript.challenge_sized(b"a", n);

        let mut rng = rekey_rng(&transcript);

        let u = random_scalars(n, &mut rng);
        let t = random_scalars(n, &mut rng);

        let shift = Permutation::shift(n, secrets.k);
        let mut sa = a.clone();
        shift.apply_to(&mut sa);

        let h: Vec<_> = sa
            .iter()
            .zip(u.iter())
            .map(|(a, u)| com.commit_by(&[*a], &u))
            .collect();
        transcript.commit(b"h", &h);
        let z: Vec<_> = publics
            .e1
            .iter()
            .zip(t.iter().zip(sa.iter()))
            .map(|(de, (t, a))| de * a + gh * t)
            .collect();
        transcript.commit(b"z", &z);
        let v = sa
            .iter()
            .zip(secrets.r.iter())
            .zip(t.iter())
            .map(|((a, r), t)| a * r + t)
            .sum::<Scalar>();
        transcript.commit(b"v", &v);

        let mut rng = rekey_rng(&transcript);

        let o = random_scalars(n, &mut rng);
        let p = random_scalars(n, &mut rng);
        let m = random_scalars(n, &mut rng);

        let f: Vec<_> = o
            .iter()
            .zip(p.iter())
            .map(|(o, p)| com.commit_by(&[*o], p))
            .collect();
        transcript.commit(b"f", &f);
        let ff: Vec<_> = publics
            .e1
            .iter()
            .zip(o.iter().zip(m.iter()))
            .map(|(de, (o, m))| de * o + gh * m)
            .collect();
        transcript.commit(b"ff", &ff);

        let l: Scalar = transcript.challenge(b"l");
        let tau: Vec<_> = o.iter().zip(sa.iter()).map(|(o, a)| o + l * a).collect();
        transcript.commit(b"tau", &tau);
        let rho: Vec<_> = p.iter().zip(u.iter()).map(|(p, u)| p + l * u).collect();
        transcript.commit(b"rho", &rho);
        let mu: Vec<_> = m.iter().zip(t.iter()).map(|(m, t)| m + l * t).collect();
        transcript.commit(b"mu", &mu);

        let rkc = known_rotation::Proof::create(
            transcript,
            known_rotation::Publics {
                com: &com,
                m: &a,
                c: &h,
            },
            known_rotation::Secrets {
                k: secrets.k,
                r: &u,
            },
        );

        Self {
            rkc,
            h,
            z,
            v,
            f,
            ff,
            tau,
            rho,
            mu,
        }
    }

    /// Verifies a non-interactive zero-knowledge proof of a shuffle of known
    /// content
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<()> {
        transcript.domain_sep(b"secret_rotation");

        transcript.commit(b"h", publics.h);
        transcript.commit(b"e0", publics.e0);
        transcript.commit(b"e1", publics.e1);

        let com: Pedersen = transcript.challenge_sized(b"com", 1);

        let n = publics.e0.len();
        let gh = Mask(G.basepoint(), *publics.h);

        let a: Vec<Scalar> = transcript.challenge_sized(b"a", n);

        transcript.commit(b"h", &self.h);
        transcript.commit(b"z", &self.z);
        transcript.commit(b"v", &self.v);

        transcript.commit(b"f", &self.f);
        transcript.commit(b"ff", &self.ff);

        let l: Scalar = transcript.challenge(b"l");

        transcript.commit(b"tau", &self.tau);
        transcript.commit(b"rho", &self.rho);
        transcript.commit(b"mu", &self.mu);

        self.rkc.verify(transcript, known_rotation::Publics {
            com: &com,
            m: &a,
            c: &self.h,
        })?;

        let tr: Vec<_> = self
            .tau
            .iter()
            .zip(self.rho.iter())
            .map(|(t, r)| com.commit_by(&[*t], r))
            .collect();
        let fhl: Vec<_> = self
            .f
            .iter()
            .zip(self.h.iter())
            .map(|(f, h)| f + h * l)
            .collect();

        let dtm: Vec<_> = publics
            .e1
            .iter()
            .zip(self.tau.iter().zip(self.mu.iter()))
            .map(|(de, (t, m))| de * t + gh * m)
            .collect();
        let fzl: Vec<_> = self
            .ff
            .iter()
            .zip(self.z.iter())
            .map(|(f, z)| f + z * l)
            .collect();

        let pzea = self
            .z
            .iter()
            .zip(publics.e0.iter())
            .zip(a.iter())
            .map(|((z, e), a)| z + e * -a)
            .sum::<Mask>();
        let ghv = gh * self.v;
        if tr == fhl && dtm == fzl && pzea == ghv {
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
        crypto::{perm::Permutation, vtmf::Mask},
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
        let k = rng.gen_range(0..8);
        let pi = Permutation::shift(8, k);
        pi.apply_to(&mut e1);
        pi.apply_to(&mut r);

        let publics = Publics {
            h,
            e0: &e0,
            e1: &e1,
        };
        let secrets = Secrets { k, r: &r };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.v += Scalar::one();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(Error::BadProof));
    }
}
