//! 1-of-2 proof of equality of discrete logarithms

use super::{TranscriptProtocol, TranscriptRngProtocol};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;
use subtle::ConditionallySelectable;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    c1: Scalar,
    r1: Scalar,
    c2: Scalar,
    r2: Scalar,
}

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    pub a1: &'a RistrettoPoint,
    pub b1: &'a RistrettoPoint,
    pub a2: &'a RistrettoPoint,
    pub b2: &'a RistrettoPoint,
    pub g: &'a RistrettoPoint,
    pub h: &'a RistrettoPoint,
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    pub is_first: bool,
    pub x: &'a Scalar,
}

impl Proof {
    /// Generates a 1-of-2 non-interactive zero-knowledge proof of equality of
    /// discrete logarithms
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"dlog_eq_1of2");

        transcript.commit_point(b"a1", publics.a1);
        transcript.commit_point(b"b1", publics.b1);
        transcript.commit_point(b"a2", publics.a2);
        transcript.commit_point(b"b2", publics.b2);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);

        let mut rng = transcript
            .build_rng()
            .commit_bit(b"is_first", secrets.is_first)
            .commit_scalar(b"x", secrets.x)
            .finalize(&mut thread_rng());

        let choice = (secrets.is_first as u8).into();

        let v1 = Scalar::random(&mut rng);
        let v2 = Scalar::random(&mut rng);
        let w = Scalar::random(&mut rng);
        let zero = Scalar::zero();
        let w1 = Scalar::conditional_select(&w, &zero, choice);
        let w2 = Scalar::conditional_select(&zero, &w, choice);

        let t1a = publics.a1 * w1 + publics.g * v1;
        let t1b = publics.b1 * w1 + publics.h * v1;
        let t2a = publics.a2 * w2 + publics.g * v2;
        let t2b = publics.b2 * w2 + publics.h * v2;
        dbg!(t1a.compress());
        dbg!(t1b.compress());
        dbg!(t2a.compress());
        dbg!(t2b.compress());

        transcript.commit_point(b"t1a", &t1a);
        transcript.commit_point(b"t1b", &t1b);
        transcript.commit_point(b"t2a", &t2a);
        transcript.commit_point(b"t2b", &t2b);

        let c = transcript.challenge_scalar(b"c");
        let diff = c - w;
        let c1 = Scalar::conditional_select(&w, &diff, choice);
        let c2 = Scalar::conditional_select(&diff, &w, choice);

        let vcx1 = v1 - c1 * secrets.x;
        let vcx2 = v2 - c2 * secrets.x;
        let r1 = Scalar::conditional_select(&v1, &vcx1, choice);
        let r2 = Scalar::conditional_select(&vcx2, &v2, choice);

        Self { c1, r1, c2, r2 }
    }

    /// Verifies a 1-of-2 non-interactive zero-knowledge proof of equality of
    /// discrete logarithms
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"dlog_eq_1of2");

        transcript.commit_point(b"a1", publics.a1);
        transcript.commit_point(b"b1", publics.b1);
        transcript.commit_point(b"a2", publics.a2);
        transcript.commit_point(b"b2", publics.b2);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);

        let t1a = publics.a1 * self.c1 + publics.g * self.r1;
        let t1b = publics.b1 * self.c1 + publics.h * self.r1;
        let t2a = publics.a2 * self.c2 + publics.g * self.r2;
        let t2b = publics.b2 * self.c2 + publics.h * self.r2;
        dbg!(t1a.compress());
        dbg!(t1b.compress());
        dbg!(t2a.compress());
        dbg!(t2b.compress());

        transcript.commit_point(b"t1a", &t1a);
        transcript.commit_point(b"t1b", &t1b);
        transcript.commit_point(b"t2a", &t2a);
        transcript.commit_point(b"t2b", &t2b);

        let c = transcript.challenge_scalar(b"c");

        if c == self.c1 + self.c2 {
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
        let y = &Scalar::random(&mut rng);
        //dbg!((g, h, x, y));

        let a1 = &(g * x);
        let b1 = &(h * x);
        let a2 = &(g * y);
        let b2 = &(h * y);

        // test first
        let publics = Publics {
            a1,
            b1,
            a2,
            b2,
            g,
            h,
        };
        let secrets = Secrets { is_first: true, x };
        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // test second
        let secrets = Secrets { is_first: false, x: y };
        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let secrets = Secrets { is_first: false, x };
        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
