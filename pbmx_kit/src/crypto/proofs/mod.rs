//! Zero-knowledge proofs

#![allow(clippy::many_single_char_names)]

pub mod dlog_eq;
mod dlog_eq_1of2;
pub mod entanglement;
mod known_rotation;
mod known_shuffle;
pub mod secret_insertion;
pub mod secret_rotation;
pub mod secret_shuffle;

use crate::crypto::{commit::Pedersen, perm::Permutation, vtmf::Mask};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::{Transcript, TranscriptRngBuilder};
use rand::{CryptoRng, Rng};
use std::iter;

trait TranscriptProtocol {
    fn domain_sep(&mut self, domain: &'static [u8]);
    fn commit_point(&mut self, label: &'static [u8], point: &RistrettoPoint);
    fn commit_points(&mut self, label: &'static [u8], points: &[RistrettoPoint]);
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn commit_scalars(&mut self, label: &'static [u8], scalars: &[Scalar]);
    fn commit_mask(&mut self, label: &'static [u8], mask: &Mask);
    fn commit_masks(&mut self, label: &'static [u8], masks: &[Mask]);
    fn commit_pedersen(&mut self, label: &'static [u8], com: &Pedersen);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    fn challenge_scalars(&mut self, label: &'static [u8], n: usize) -> Vec<Scalar>;
    fn challenge_point(&mut self, label: &'static [u8]) -> RistrettoPoint;
    fn challenge_pedersen(&mut self, label: &'static [u8], h: RistrettoPoint, n: usize)
        -> Pedersen;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, domain: &'static [u8]) {
        self.append_message(b"$domain", domain);
    }

    fn commit_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.append_message(label, point.compress().as_bytes());
    }

    fn commit_points(&mut self, label: &'static [u8], points: &[RistrettoPoint]) {
        self.append_message(b"$vec", &points.len().to_le_bytes());
        for p in points.iter() {
            self.commit_point(label, &p);
        }
    }

    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn commit_scalars(&mut self, label: &'static [u8], scalars: &[Scalar]) {
        self.append_message(b"$vec", &scalars.len().to_le_bytes());
        for s in scalars.iter() {
            self.commit_scalar(label, s);
        }
    }

    fn commit_mask(&mut self, label: &'static [u8], mask: &Mask) {
        self.append_message(b"$tuple", &[2]);
        self.append_message(label, mask.0.compress().as_bytes());
        self.append_message(label, mask.1.compress().as_bytes());
    }

    fn commit_masks(&mut self, label: &'static [u8], masks: &[Mask]) {
        self.append_message(b"$vec", &masks.len().to_le_bytes());
        for m in masks.iter() {
            self.commit_mask(label, m);
        }
    }

    fn commit_pedersen(&mut self, label: &'static [u8], com: &Pedersen) {
        self.append_message(b"$pedersen", label);
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

    fn challenge_point(&mut self, label: &'static [u8]) -> RistrettoPoint {
        let s = self.challenge_scalar(label);
        &RISTRETTO_BASEPOINT_TABLE * &s
    }

    fn challenge_pedersen(
        &mut self,
        label: &'static [u8],
        h: RistrettoPoint,
        n: usize,
    ) -> Pedersen {
        loop {
            let com = Pedersen::new(
                h,
                iter::repeat_with(|| self.challenge_point(label))
                    .take(n)
                    .collect(),
            );
            if let Some(com) = com {
                return com;
            }
        }
    }
}

trait TranscriptRngProtocol {
    fn commit_bit(self, label: &'static [u8], bit: bool) -> Self;
    fn commit_index(self, label: &'static [u8], index: usize) -> Self;
    fn commit_scalar(self, label: &'static [u8], scalar: &Scalar) -> Self;
    fn commit_scalars(self, label: &'static [u8], scalars: &[Scalar]) -> Self;
    fn commit_mask(self, label: &'static [u8], mask: &Mask) -> Self;
    fn commit_masks(self, label: &'static [u8], masks: &[Mask]) -> Self;
    fn commit_permutation(self, label: &'static [u8], perm: &Permutation) -> Self;
}

impl TranscriptRngProtocol for TranscriptRngBuilder {
    fn commit_bit(self, label: &'static [u8], bit: bool) -> Self {
        self.commit_index(label, bit as usize)
    }

    fn commit_index(self, label: &'static [u8], index: usize) -> Self {
        self.rekey_with_witness_bytes(label, &index.to_be_bytes())
    }

    fn commit_scalar(self, label: &'static [u8], scalar: &Scalar) -> Self {
        self.rekey_with_witness_bytes(label, scalar.as_bytes())
    }

    fn commit_scalars(self, label: &'static [u8], scalars: &[Scalar]) -> Self {
        let mut builder = self.rekey_with_witness_bytes(b"$vec", &scalars.len().to_le_bytes());
        for s in scalars.iter() {
            builder = builder.commit_scalar(label, s);
        }
        builder
    }

    fn commit_mask(self, label: &'static [u8], mask: &Mask) -> Self {
        self.rekey_with_witness_bytes(b"$tuple", &[2])
            .rekey_with_witness_bytes(label, mask.0.compress().as_bytes())
            .rekey_with_witness_bytes(label, mask.1.compress().as_bytes())
    }

    fn commit_masks(self, label: &'static [u8], masks: &[Mask]) -> Self {
        let mut builder = self.rekey_with_witness_bytes(b"$vec", &masks.len().to_le_bytes());
        for m in masks.iter() {
            builder = builder.commit_mask(label, m);
        }
        builder
    }

    fn commit_permutation(self, label: &'static [u8], perm: &Permutation) -> Self {
        let mut builder = self.rekey_with_witness_bytes(b"$perm", &perm.len().to_le_bytes());
        for p in perm.iter() {
            builder = builder.commit_index(label, *p);
        }
        builder
    }
}

fn random_scalars<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Vec<Scalar> {
    iter::repeat_with(|| Scalar::random(rng)).take(n).collect()
}
