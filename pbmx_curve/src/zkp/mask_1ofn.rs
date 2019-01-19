//! Zero-knowledge proof of equality of discrete logarithms

use super::{TranscriptProtocol, TranscriptRngProtocol};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    c: Vec<Scalar>,
    r: Vec<Scalar>,
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
    /// Domain
    pub m: &'a [Scalar],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Exponent
    pub x: &'a Scalar,
    /// Index
    pub i: usize,
}

impl Proof {
    /// Generates a witness hidding non-interactive zero-knowledge proof that an
    /// i exists such that log_g(x) = log_h(y*g^-m_i)
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"mask_1ofn");

        transcript.commit_point(b"a", publics.a);
        transcript.commit_point(b"b", publics.b);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);
        transcript.commit_scalars(b"m", publics.m);

        let mut rng = transcript
            .build_rng()
            .commit_scalar(b"x", secrets.x)
            .finalize(&mut thread_rng());

        let (vw, t): (Vec<_>, Vec<_>) = publics
            .m
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let v = Scalar::random(&mut rng);
                let w = if i == secrets.i {
                    Scalar::zero()
                } else {
                    Scalar::random(&mut rng)
                };
                let t0 = publics.a * w + publics.g * v;
                let gm = publics.g * m;
                let bgm = publics.b - gm;
                let t1 = bgm * w + publics.h * v;
                ((v, w), (t0, t1))
            })
            .unzip();
        transcript.commit_masks(b"t", &t);
        let (v, w): (Vec<_>, Vec<_>) = vw.into_iter().unzip();

        let c = transcript.challenge_scalar(b"c");
        let ci = c - w.iter().sum::<Scalar>();
        let c: Vec<_> = w
            .into_iter()
            .enumerate()
            .map(|(i, w)| if i == secrets.i { ci } else { w })
            .collect();

        let r: Vec<_> = v
            .into_iter()
            .zip(c.iter())
            .enumerate()
            .map(|(i, (v, c))| if i == secrets.i { v - c * secrets.x } else { v })
            .collect();

        Self { c, r }
    }

    /// Verifies a witness hidding non-interactive zero-knowledge proof that an
    /// i exists such that log_g(x) = log_h(y * g^-m_i)
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"mask_1ofn");

        transcript.commit_point(b"a", publics.a);
        transcript.commit_point(b"b", publics.b);
        transcript.commit_point(b"g", publics.g);
        transcript.commit_point(b"h", publics.h);
        transcript.commit_scalars(b"m", publics.m);

        let t: Vec<_> = self
            .c
            .iter()
            .zip(self.r.iter())
            .zip(publics.m.iter())
            .map(|((c, r), m)| {
                let t0 = publics.a * c + publics.g * r;
                let gm = publics.g * m;
                let bgm = publics.b - gm;
                let t1 = bgm * c + publics.h * r;
                (t0, t1)
            })
            .collect();
        transcript.commit_masks(b"t", &t);

        let c = transcript.challenge_scalar(b"c");
        let c_sum = self.c.iter().sum::<Scalar>();

        if c == c_sum {
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
    use rand::{thread_rng, Rng};
    use std::iter;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let g = &RistrettoPoint::random(&mut rng);
        let h = &RistrettoPoint::random(&mut rng);
        let x = &Scalar::random(&mut rng);
        dbg!((g, h, x));

        let m = &iter::repeat_with(|| Scalar::random(&mut rng))
            .take(8)
            .collect::<Vec<_>>();
        let i = rng.gen_range(0, 8);
        dbg!(i);

        let a = &(g * x);
        let b = &(h * x + g * m[i]);

        let publics = Publics { a, b, g, h, m };
        let secrets = Secrets { x, i };

        let mut proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        proof.r[0] += Scalar::one();
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
