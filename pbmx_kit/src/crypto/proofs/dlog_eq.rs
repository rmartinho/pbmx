//! Chaum and Pedersen's zero-knowledge proof of equality of discrete logarithms

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::proto;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    c: Scalar,
    r: Scalar,
}

derive_opaque_proto_conversions!(Proof: proto::DlogEqProof);

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
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
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
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Proof, Publics, Secrets};
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
        assert_eq!(verified, Err(()));
    }
}
