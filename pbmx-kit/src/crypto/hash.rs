//! Cryptographic hash functions

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use digest::XofReader;
use merlin::Transcript;

/// A STROBE-based hash function
pub struct TranscriptHash(Transcript);

/// A type that can be hashed using STROBE
pub trait TranscriptHashable {
    /// Appends this object for hashing, with a given label for framing
    fn append_to_hash(&self, h: &mut TranscriptHash, label: &'static [u8]) {
        self.append_to_transcript(&mut h.0, label);
    }

    /// Appends this object to a transcript, with a given label for framing
    fn append_to_transcript(&self, h: &mut Transcript, label: &'static [u8]);
}

impl TranscriptHash {
    /// Creates a new hash object
    pub fn new(protocol: &'static [u8]) -> Self {
        Self(Transcript::new(protocol))
    }

    /// Appends an object for hashing, with a given label for framing
    pub fn append<M: TranscriptHashable>(&mut self, label: &'static [u8], m: &M) {
        m.append_to_hash(self, label);
    }

    /// Produces a fixed-size hash from all the data that was appended
    pub fn finish(mut self, buffer: &mut [u8]) {
        self.0.challenge_bytes(b"$hash", buffer);
    }

    /// Creates a XOF reader object to produce a variable-size hash
    pub fn into_xof(self) -> impl XofReader {
        TranscriptXof(self.0)
    }
}

impl<T: TranscriptHashable> TranscriptHashable for [T] {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        b"vec".append_to_transcript(t, label);
        self.len().append_to_transcript(t, b"$len");
        for e in self.iter() {
            e.append_to_transcript(t, b"element");
        }
    }
}

impl<'a, T: TranscriptHashable> TranscriptHashable for &'a T {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        (*self).append_to_transcript(t, label);
    }
}

impl TranscriptHashable for usize {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_u64(label, *self as u64);
    }
}

impl TranscriptHashable for [u8] {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_message(label, &self);
    }
}

impl TranscriptHashable for str {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_message(label, self.as_bytes());
    }
}

impl TranscriptHashable for Scalar {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        b"scalar".append_to_transcript(t, label);
        self.as_bytes().append_to_transcript(t, b"bytes");
    }
}

impl TranscriptHashable for RistrettoPoint {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        b"point".append_to_transcript(t, label);
        self.compress().as_bytes().append_to_transcript(t, b"bytes");
    }
}

struct TranscriptXof(Transcript);

impl XofReader for TranscriptXof {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.challenge_bytes(b"$xof", buffer);
    }
}
