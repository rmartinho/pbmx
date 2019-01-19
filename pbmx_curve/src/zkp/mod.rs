//! Zero-knowledge proofs

pub mod dlog_eq;
mod known_shuffle;
pub mod mask_1ofn;
pub mod secret_shuffle;

use crate::{commit::Pedersen, perm::Permutation, vtmf::Mask};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::{Transcript, TranscriptRngBuilder};
use std::iter;

trait TranscriptProtocol {
    fn domain_sep(&mut self, domain: &'static [u8]);
    fn commit_point(&mut self, label: &'static [u8], point: &RistrettoPoint);
    fn commit_points(&mut self, label: &'static [u8], points: &[RistrettoPoint]);
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn commit_scalars(&mut self, label: &'static [u8], scalars: &[Scalar]);
    fn commit_mask(&mut self, label: &'static [u8], masks: &Mask);
    fn commit_masks(&mut self, label: &'static [u8], masks: &[Mask]);
    fn commit_pedersen(&mut self, label: &'static [u8], com: &Pedersen);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    fn challenge_scalars(&mut self, label: &'static [u8], n: usize) -> Vec<Scalar>;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, domain: &'static [u8]) {
        self.commit_bytes(b"$domain", domain);
    }

    fn commit_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.commit_bytes(label, point.compress().as_bytes());
    }

    fn commit_points(&mut self, label: &'static [u8], points: &[RistrettoPoint]) {
        self.commit_bytes(b"$vec", &points.len().to_le_bytes());
        for p in points.iter() {
            self.commit_point(label, &p);
        }
    }

    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.commit_bytes(label, scalar.as_bytes());
    }

    fn commit_scalars(&mut self, label: &'static [u8], scalars: &[Scalar]) {
        self.commit_bytes(b"$vec", &scalars.len().to_le_bytes());
        for s in scalars.iter() {
            self.commit_scalar(label, s);
        }
    }

    fn commit_mask(&mut self, label: &'static [u8], mask: &Mask) {
        self.commit_bytes(b"$tuple", &[2]);
        self.commit_bytes(label, mask.0.compress().as_bytes());
        self.commit_bytes(label, mask.1.compress().as_bytes());
    }

    fn commit_masks(&mut self, label: &'static [u8], masks: &[Mask]) {
        self.commit_bytes(b"$vec", &masks.len().to_le_bytes());
        for m in masks.iter() {
            self.commit_mask(label, m);
        }
    }

    fn commit_pedersen(&mut self, label: &'static [u8], com: &Pedersen) {
        self.commit_bytes(b"$pedersen", label);
        self.commit_point(label, com.shared_point());
        self.commit_points(label, com.points());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn challenge_scalars(&mut self, label: &'static [u8], n: usize) -> Vec<Scalar> {
        iter::repeat_with(|| self.challenge_scalar(label))
            .take(n)
            .collect()
    }
}

trait TranscriptRngProtocol {
    fn commit_index(self, label: &'static [u8], index: usize) -> Self;
    fn commit_scalar(self, label: &'static [u8], scalar: &Scalar) -> Self;
    fn commit_scalars(self, label: &'static [u8], scalars: &[Scalar]) -> Self;
    fn commit_permutation(self, label: &'static [u8], perm: &Permutation) -> Self;
}

impl TranscriptRngProtocol for TranscriptRngBuilder {
    fn commit_index(self, label: &'static [u8], index: usize) -> Self {
        self.commit_witness_bytes(label, &index.to_be_bytes())
    }

    fn commit_scalar(self, label: &'static [u8], scalar: &Scalar) -> Self {
        self.commit_witness_bytes(label, scalar.as_bytes())
    }

    fn commit_scalars(self, label: &'static [u8], scalars: &[Scalar]) -> Self {
        let mut builder = self.commit_witness_bytes(b"$vec", &scalars.len().to_le_bytes());
        for s in scalars.iter() {
            builder = builder.commit_scalar(label, s);
        }
        builder
    }

    fn commit_permutation(self, label: &'static [u8], perm: &Permutation) -> Self {
        let mut builder = self.commit_witness_bytes(b"$perm", &perm.len().to_le_bytes());
        for p in perm.iter() {
            builder = builder.commit_index(label, *p);
        }
        builder
    }
}
