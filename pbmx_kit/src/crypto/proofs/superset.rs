//! Superset proof

use super::{TranscriptProtocol, TranscriptRngProtocol};
use crate::{
    crypto::{
        perm::{Permutation, Shuffles},
        proofs::secret_shuffle,
        vtmf::Mask,
    },
    proto,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
};
use merlin::Transcript;
use rand::{thread_rng, Rng};
use std::convert::TryFrom;

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

/// Non-interactive proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    shuffle: Vec<Mask>,
    proof: secret_shuffle::Proof,
}

derive_opaque_proto_conversions!(Proof: proto::SupersetProof);

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// Superset stack
    pub sup: &'a [Mask],
    /// Subset stack
    pub sub: &'a [Mask],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Indices of subset elements in the superset
    pub idx: &'a [usize],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge superset proof
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"superset");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"sup", publics.sup);
        transcript.commit_masks(b"sub", publics.sub);

        let mut rng = transcript
            .build_rng()
            .commit_indices(b"idx", secrets.idx)
            .finalize(&mut thread_rng());

        let gh = Mask(G.basepoint(), *publics.h);

        let mut perm = secrets.idx.to_vec();
        let mut extra: Vec<_> = (0..publics.sup.len())
            .filter(|i| !secrets.idx.contains(i))
            .collect();
        rng.sample(Shuffles(extra.len())).apply_to(&mut extra);
        perm.extend_from_slice(&extra);
        let pi = Permutation::try_from(perm).unwrap();

        let mut r = super::random_scalars(publics.sup.len(), &mut rng);
        let mut shuffle: Vec<_> = publics
            .sup
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
                e0: &publics.sup,
                e1: &shuffle,
            },
            secret_shuffle::Secrets { pi: &pi, r: &r },
        );

        Self { shuffle, proof }
    }

    /// Verifies a non-interactive zero-knowledge proof of a secret shuffle
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"superset");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"sup", publics.sup);
        transcript.commit_masks(b"sub", publics.sub);

        self.proof.verify(transcript, secret_shuffle::Publics {
            h: publics.h,
            e0: &publics.sup,
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

        let sub: Vec<_> = (0..3).map(|t| Mask::open(map::to_curve(t))).collect();
        let sup: Vec<_> = (0..8)
            .map(|t| {
                let r = Scalar::random(&mut rng);
                gh * r + Mask::open(map::to_curve(t))
            })
            .collect();
        let idx: Vec<_> = (0..8).collect();

        let publics = Publics {
            h: &h,
            sup: &sup,
            sub: &sub,
        };
        let secrets = Secrets { idx: &idx };

        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let bad_sub = (0..3)
            .map(|t| Mask::open(map::to_curve(t)))
            .collect::<Vec<_>>();
        let mut publics = publics;
        publics.sub = &bad_sub;
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
