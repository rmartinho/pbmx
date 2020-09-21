//! Zero-knowledge proof of equality of discrete logarithms
///
// [CS97] Jan Camenisch, Markus Stadler:
//          'Proof Systems for General Statements about Discrete Logarithms',
//          Technical Report, 1997.
use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    crypto::hash::TranscriptHashable,
    proto,
    random::thread_rng,
    serde::{scalar_from_proto, scalar_to_proto, Proto},
    Error, Result,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    c: Scalar,
    r: Scalar,
}

impl Proto for Proof {
    type Message = proto::DlogEqProof;

    fn to_proto(&self) -> Result<proto::DlogEqProof> {
        Ok(proto::DlogEqProof {
            c: scalar_to_proto(&self.c)?,
            r: scalar_to_proto(&self.r)?,
        })
    }

    fn from_proto(m: &proto::DlogEqProof) -> Result<Self> {
        Ok(Proof {
            c: scalar_from_proto(&m.c)?,
            r: scalar_from_proto(&m.r)?,
        })
    }
}

impl TranscriptHashable for Proof {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        b"dlog-eq-proof".append_to_transcript(t, label);
        self.c.append_to_transcript(t, b"c");
        self.r.append_to_transcript(t, b"r");
    }
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// First point
    pub a: &'a RistrettoPoint,
    /// Second point
    pub b: &'a RistrettoPoint,
    /// First point's base
    pub g: &'a RistrettoPoint,
    /// Second point's base
    pub h: &'a RistrettoPoint,
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Discrete logarithm
    pub x: &'a Scalar,
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof of equality of discrete
    /// logarithms
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"dlog_eq");

        transcript.commit_point(b"a", publics.a);
        transcript.commit_point(b"b", publics.b);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);

        let mut rng = transcript
            .build_rng()
            .commit_scalar(b"x", secrets.x)
            .finalize(&mut thread_rng());

        let w = Scalar::random(&mut rng);

        let t1 = publics.g * w;
        let t2 = publics.h * w;

        transcript.commit_point(b"t1", &t1);
        transcript.commit_point(b"t2", &t2);

        let c = transcript.challenge_scalar(b"c");
        let r = w - c * secrets.x;

        Self { c, r }
    }

    /// Verifies a 1-of-2 non-interactive zero-knowledge proof of equality of
    /// discrete logarithms
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<()> {
        transcript.domain_sep(b"dlog_eq");

        transcript.commit_point(b"a", publics.a);
        transcript.commit_point(b"b", publics.b);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);

        let t1 = publics.a * self.c + publics.g * self.r;
        let t2 = publics.b * self.c + publics.h * self.r;

        transcript.commit_point(b"t1", &t1);
        transcript.commit_point(b"t2", &t2);

        let c = transcript.challenge_scalar(b"c");

        if c == self.c {
            Ok(())
        } else {
            Err(Error::BadProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Proof, Publics, Secrets};
    use crate::Error;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::thread_rng;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let g = &RistrettoPoint::random(&mut rng);
        let h = &RistrettoPoint::random(&mut rng);
        let x = &Scalar::random(&mut rng);

        let a = &(g * x);
        let b = &(h * x);
        let publics = Publics { a, b, g, h };
        let secrets = Secrets { x };

        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let proof = Proof::create(&mut Transcript::new(b"test"), publics, Secrets {
            x: &Scalar::one(),
        });
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(Error::BadProof));
    }
}
