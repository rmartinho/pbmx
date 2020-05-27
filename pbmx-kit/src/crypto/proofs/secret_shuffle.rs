//! Verifiable secret shuffle of homomorphic encryptions

// [Gr05] Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
//          Cryptology ePrint Archive, Report 2005/246, 2005.

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    crypto::{perm::Permutation, proofs::known_shuffle, vtmf::Mask},
    proto,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::thread_rng;
use std::iter;

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    skc: known_shuffle::Proof,
    c: RistrettoPoint,
    cd: RistrettoPoint,
    ed: Mask,
    f: Vec<Scalar>,
    z: Scalar,
}

derive_opaque_proto_conversions!(Proof: proto::ShuffleProof);

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

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"e0", publics.e0);
        transcript.commit_masks(b"e1", publics.e1);

        let n = publics.e0.len();
        let com = transcript.challenge_pedersen(b"com", *publics.h, n);

        let rekey_rng = |t: &Transcript| {
            t.build_rng()
                .commit_permutation(b"pi", secrets.pi)
                .commit_scalars(b"r", secrets.r)
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
        transcript.commit_point(b"c", &c);

        let mut rng = rekey_rng(&transcript);

        let d: Vec<_> = iter::repeat_with(|| Scalar::random(&mut rng))
            .map(|d| -d)
            .take(n)
            .collect();
        let (cd, rd) = com.commit_to(&d, &mut rng);
        transcript.commit_point(b"cd", &cd);

        let ed = gh * rd
            + d.iter()
                .zip(publics.e1.iter())
                .map(|(d, e)| e * d)
                .sum::<Mask>();
        transcript.commit_mask(b"ed", &ed);

        let t = transcript.challenge_scalars(b"t", n);

        let f: Vec<_> = secrets
            .pi
            .iter()
            .zip(d.iter())
            .map(|(p, d)| t[*p] - d)
            .collect();
        transcript.commit_scalars(b"f", &f);

        let z = secrets
            .pi
            .iter()
            .zip(secrets.r.iter())
            .map(|(p, r)| t[*p] * r)
            .sum::<Scalar>()
            + rd;
        transcript.commit_scalar(b"z", &z);

        let l = transcript.challenge_scalar(b"l");

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
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"secret_shuffle");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"e0", publics.e0);
        transcript.commit_masks(b"e1", publics.e1);

        let n = publics.e0.len();
        let com = transcript.challenge_pedersen(b"com", *publics.h, n);

        let gh = Mask(G.basepoint(), *publics.h);

        transcript.commit_point(b"c", &self.c);
        transcript.commit_point(b"cd", &self.cd);
        transcript.commit_mask(b"ed", &self.ed);

        let t = transcript.challenge_scalars(b"t", n);

        transcript.commit_scalars(b"f", &self.f);
        transcript.commit_scalar(b"z", &self.z);

        let l = transcript.challenge_scalar(b"l");

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
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::random_scalars, Proof, Publics, Secrets, G};
    use crate::crypto::{perm::Shuffles, vtmf::Mask};
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
        assert_eq!(verified, Err(()));
    }
}
