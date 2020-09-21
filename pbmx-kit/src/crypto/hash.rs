//! Cryptographic hash functions

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use digest::XofReader;
use merlin::{Transcript};

use std::iter;

/// A transcript that can be appended to.
pub trait TranscriptAppend {
    /// Appends a message to this transcript
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);
}

impl TranscriptAppend for Transcript {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        Transcript::append_message(self, label, message);
    }
}

impl TranscriptAppend for TranscriptHash {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.0.append_message(label, message);
    }
}

/// A STROBE-based hash function
pub struct TranscriptHash(Transcript);

impl TranscriptHash {
    /// Creates a new hash object
    pub fn new(protocol: &'static [u8]) -> Self {
        Self(Transcript::new(protocol))
    }

    /// Appends an object for hashing, with a given label for framing
    pub fn append<M: Transcribe>(&mut self, label: &'static [u8], m: &M) {
        m.append_to_transcript(self, label);
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

struct TranscriptXof(Transcript);

impl XofReader for TranscriptXof {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.challenge_bytes(b"$xof", buffer);
    }
}

/// A type that can be hashed using a STROBE
pub trait Transcribe {
    /// Appends this object to a transcript, with a given label for framing
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]);
}

/// A type that can be retrieved from a STROBE
pub trait Challenge: Sized {
    /// Reads a value from a transcript, with a given label for framing
    fn read_from_transcript(t: &mut Transcript, label: &'static [u8]) -> Self {
        Self::read_from_transcript_sized(t, label, 1)
    }

    /// Reads a value from a transcript, with a given label for framing, and a
    /// pre-determined size
    fn read_from_transcript_sized(t: &mut Transcript, label: &'static [u8], _: usize) -> Self {
        Self::read_from_transcript(t, label)
    }
}

impl<T: Transcribe> Transcribe for [T] {
    fn append_to_transcript<A: TranscriptAppend>(&self, t: &mut A, label: &'static [u8]) {
        b"vec".append_to_transcript(t, label);
        self.len().append_to_transcript(t, b"$len");
        for e in self.iter() {
            e.append_to_transcript(t, b"element");
        }
    }
}

impl<T: Transcribe> Transcribe for Vec<T> {
    fn append_to_transcript<A: TranscriptAppend>(&self, t: &mut A, label: &'static [u8]) {
        self.as_slice().append_to_transcript(t, label);
    }
}

impl<'a, T: Transcribe> Transcribe for &'a T {
    fn append_to_transcript<A: TranscriptAppend>(&self, t: &mut A, label: &'static [u8]) {
        (*self).append_to_transcript(t, label);
    }
}

impl Transcribe for bool {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        t.append_message(label, &[*self as u8]);
    }
}

impl Transcribe for usize {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        t.append_message(label, &(*self as u64).to_be_bytes());
    }
}

impl Transcribe for [u8] {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        t.append_message(label, &self);
    }
}

impl Transcribe for str {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        t.append_message(label, self.as_bytes());
    }
}
impl Transcribe for String {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        self.as_str().append_to_transcript(t, label);
    }
}

impl Transcribe for Scalar {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        b"scalar".append_to_transcript(t, label);
        self.as_bytes().append_to_transcript(t, b"bytes");
    }
}

impl Transcribe for RistrettoPoint {
    fn append_to_transcript<T: TranscriptAppend>(&self, t: &mut T, label: &'static [u8]) {
        b"point".append_to_transcript(t, label);
        self.compress().as_bytes().append_to_transcript(t, b"bytes");
    }
}

impl<T: Challenge> Challenge for Vec<T> {
    fn read_from_transcript_sized(t: &mut Transcript, label: &'static [u8], n: usize) -> Self {
        b"vec".append_to_transcript(t, label);
        n.append_to_transcript(t, b"$len");
        iter::repeat_with(|| T::read_from_transcript(t, b"element"))
            .take(n)
            .collect()
    }
}

impl Challenge for Scalar {
    fn read_from_transcript(t: &mut Transcript, label: &'static [u8]) -> Self {
        b"scalar".append_to_transcript(t, label);
        let mut buf = [0; 64];
        t.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

impl Challenge for RistrettoPoint {
    fn read_from_transcript(t: &mut Transcript, label: &'static [u8]) -> Self {
        b"point".append_to_transcript(t, label);
        let s = Scalar::read_from_transcript(t, b"exponent");
        &RISTRETTO_BASEPOINT_TABLE * &s
    }
}
