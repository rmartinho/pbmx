//! Disjoint set proof

use super::TranscriptProtocol;
use crate::{
    crypto::{perm::Shuffles, proofs::secret_shuffle, vtmf::Mask},
    proto,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
};
use merlin::Transcript;
use rand::{thread_rng, Rng};

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    shuffle: Vec<Mask>,
    proof: secret_shuffle::Proof,
}

derive_opaque_proto_conversions!(Proof: proto::DisjointProof);

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// First stack
    pub s0: &'a [Mask],
    /// Second stack
    pub s1: &'a [Mask],
    /// Universe stack
    pub u: &'a [Mask],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets {}

impl Proof {
    /// Generates a non-interactive zero-knowledge disjoint stacks proof
    pub fn create(transcript: &mut Transcript, publics: Publics, _secrets: Secrets) -> Self {
        transcript.domain_sep(b"disjoint");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"u", publics.u);
        transcript.commit_masks(b"s0", publics.s0);
        transcript.commit_masks(b"s1", publics.s1);

        let mut rng = transcript.build_rng().finalize(&mut thread_rng());

        let gh = Mask(G.basepoint(), *publics.h);

        let mut stacked = publics.s0.to_vec();
        stacked.extend_from_slice(publics.s1);
        transcript.commit_masks(b"stacked", &stacked);

        let pi = rng.sample(&Shuffles(stacked.len()));
        let mut r = super::random_scalars(stacked.len(), &mut rng);

        let mut shuffle: Vec<_> = stacked
            .iter()
            .zip(r.iter())
            .map(|(c, r)| gh * r + c)
            .collect();
        pi.apply_to(&mut shuffle);
        pi.apply_to(&mut r);

        let proof = secret_shuffle::Proof::create(
            transcript,
            secret_shuffle::Publics {
                h: publics.h,
                e0: &stacked,
                e1: &shuffle,
            },
            secret_shuffle::Secrets { pi: &pi, r: &r },
        );

        Self { shuffle, proof }
    }

    /// Verifies a non-interactive zero-knowledge proof of a secret shuffle
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"disjoint");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"u", publics.u);
        transcript.commit_masks(b"s0", publics.s0);
        transcript.commit_masks(b"s1", publics.s1);

        let mut stacked = publics.s0.to_vec();
        stacked.extend_from_slice(publics.s1);
        transcript.commit_masks(b"stacked", &stacked);

        self.proof.verify(transcript, secret_shuffle::Publics {
            h: publics.h,
            e0: &stacked,
            e1: &self.shuffle,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Proof, Publics, Secrets, G};
    use crate::crypto::{map, vtmf::Mask};
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use rand::thread_rng;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let x = &Scalar::random(&mut rng);
        let h = G * x;
        let gh = Mask(G.basepoint(), h);

        let u: Vec<_> = (0..8)
            .map(|t| {
                let r = Scalar::random(&mut rng);
                gh * r + Mask::open(map::to_curve(t))
            })
            .collect();

        let publics = Publics {
            h: &h,
            u: &u,
            s0: &u[0..3],
            s1: &u[3..8],
        };
        let secrets = Secrets {};

        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let bad_s0 = (0..3)
            .map(|t| Mask::open(map::to_curve(t)))
            .collect::<Vec<_>>();
        let mut publics = publics;
        publics.s0 = &bad_s0;
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
