//! Subset proof

use super::{TranscriptProtocol, TranscriptRngProtocol};
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
    extra: Vec<Mask>,
    shuffle: Vec<Mask>,
    proof: secret_shuffle::Proof,
}

derive_opaque_proto_conversions!(Proof: proto::SubsetProof);

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// Public key
    pub h: &'a RistrettoPoint,
    /// Subset stack
    pub sub: &'a [Mask],
    /// Superset stack
    pub sup: &'a [Mask],
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Subset-superset difference
    pub diff: &'a [Mask],
}

impl Proof {
    /// Generates a non-interactive zero-knowledge subset proof
    pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Self {
        transcript.domain_sep(b"subset");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"sub", publics.sub);
        transcript.commit_masks(b"sup", publics.sup);

        let mut rng = transcript
            .build_rng()
            .commit_masks(b"diff", secrets.diff)
            .finalize(&mut thread_rng());

        let gh = Mask(G.basepoint(), *publics.h);

        let r = super::random_scalars(secrets.diff.len(), &mut rng);

        let extra: Vec<_> = secrets
            .diff
            .iter()
            .zip(r.iter())
            .map(|(c, r)| gh * r + c)
            .collect();
        let mut stacked = extra.clone();
        stacked.extend_from_slice(publics.sub);
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

        Self {
            extra,
            shuffle,
            proof,
        }
    }

    /// Verifies a non-interactive zero-knowledge subset proof
    pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
        transcript.domain_sep(b"subset");

        transcript.commit_point(b"h", publics.h);
        transcript.commit_masks(b"sub", publics.sub);
        transcript.commit_masks(b"sup", publics.sup);

        let mut stacked = self.extra.to_vec();
        stacked.extend_from_slice(publics.sub);
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

        let sup: Vec<_> = (0..8).map(|t| Mask::open(map::to_curve(t))).collect();
        let sub: Vec<_> = (0..3)
            .map(|t| {
                let r = Scalar::random(&mut rng);
                gh * r + Mask::open(map::to_curve(t))
            })
            .collect();
        let diff: Vec<_> = (3..8).map(|t| Mask::open(map::to_curve(t))).collect();

        let publics = Publics {
            h: &h,
            sub: &sub,
            sup: &sup,
        };
        let secrets = Secrets { diff: &diff };

        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let bad_sup = (0..8)
            .map(|t| Mask::open(map::to_curve(t)))
            .collect::<Vec<_>>();
        let mut publics = publics;
        publics.sup = &bad_sup;
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}
