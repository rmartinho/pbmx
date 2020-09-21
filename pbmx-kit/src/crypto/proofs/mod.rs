//! Zero-knowledge proofs

#![allow(clippy::many_single_char_names)]

pub mod dlog_eq;
pub mod entanglement;
mod known_rotation;
mod known_shuffle;
pub mod secret_rotation;
pub mod secret_shuffle;

use crate::crypto::{
    hash::{Challenge, Transcribe, TranscriptAppend},
};
use curve25519_dalek::scalar::Scalar;
use merlin::{Transcript, TranscriptRngBuilder};
use rand::{CryptoRng, Rng};
use std::iter;

trait TranscriptProtocol {
    fn domain_sep(&mut self, domain: &'static [u8]);
    fn commit<M: Transcribe + ?Sized>(&mut self, label: &'static [u8], m: &M);
    fn challenge<M: Challenge>(&mut self, label: &'static [u8]) -> M;
    fn challenge_sized<M: Challenge>(&mut self, label: &'static [u8], n: usize) -> M;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, domain: &'static [u8]) {
        self.append_message(b"$domain", domain);
    }

    fn commit<M: Transcribe + ?Sized>(&mut self, label: &'static [u8], m: &M) {
        m.append_to_transcript(self, label);
    }

    fn challenge<M: Challenge>(&mut self, label: &'static [u8]) -> M {
        M::read_from_transcript(self, label)
    }

    fn challenge_sized<M: Challenge>(&mut self, label: &'static [u8], n: usize) -> M {
        M::read_from_transcript_sized(self, label, n)
    }
}

trait TranscriptRngProtocol {
    fn rekey<M: Transcribe + ?Sized>(self, label: &'static [u8], m: &M) -> Self;
}

impl TranscriptRngProtocol for TranscriptRngBuilder {
    fn rekey<M: Transcribe + ?Sized>(self, label: &'static [u8], m: &M) -> Self {
        let mut w = wrap(self);
        m.append_to_transcript(&mut w, label);
        unwrap(w)
    }
}

struct AppendableTranscriptRngBuilder(Option<TranscriptRngBuilder>);

fn wrap(builder: TranscriptRngBuilder) -> AppendableTranscriptRngBuilder {
    AppendableTranscriptRngBuilder(Some(builder))
}

fn unwrap(builder: AppendableTranscriptRngBuilder) -> TranscriptRngBuilder {
    builder.0.unwrap()
}

impl TranscriptAppend for AppendableTranscriptRngBuilder {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        let old = self.0.take().unwrap();
        self.0.replace(old.rekey_with_witness_bytes(label, message));
    }
}

fn random_scalars<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Vec<Scalar> {
    iter::repeat_with(|| Scalar::random(rng)).take(n).collect()
}
