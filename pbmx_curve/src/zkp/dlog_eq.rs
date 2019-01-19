//! Chaum and Pedersen's zero-knowledge proof of equality of discrete logarithms

use super::{TranscriptProtocol, TranscriptRngProtocol};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    c: Scalar,
    r: Scalar,
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Power of base g
    pub a: &'a RistrettoPoint,
    /// Power of base h
    pub b: &'a RistrettoPoint,
    /// First base
    pub g: &'a RistrettoPoint,
    /// Second base
    pub h: &'a RistrettoPoint,
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Exponent
    pub x: &'a Scalar,
}

impl Proof {
    /// Generates a non-interactive zero-knowledge proof that log_g(x) =
    /// log_h(y)
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

        let gw = publics.g * w;
        let hw = publics.h * w;
        transcript.commit_point(b"g^w", &gw);
        transcript.commit_point(b"h^w", &hw);

        let c = transcript.challenge_scalar(b"c");

        let r = w - c * secrets.x;

        Self { c, r }
    }

    /// Verifies a non-interactive zero-knowledge proof that log_g(x) = log_h(y)
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"dlog_eq");

        transcript.commit_point(b"a", publics.a);
        transcript.commit_point(b"b", publics.b);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);

        let gw = publics.a * self.c + publics.g * self.r;
        let hw = publics.b * self.c + publics.h * self.r;
        transcript.commit_point(b"g^w", &gw);
        transcript.commit_point(b"h^w", &hw);

        let c = transcript.challenge_scalar(b"c");
        if self.c == c {
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
        dbg!((g, h, x));

        let a = &(g * x);
        let b = &(h * x);
        let publics = Publics { a, b, g, h };
        let secrets = Secrets { x };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.r += Scalar::one();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
