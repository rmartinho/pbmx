//! Cryptographic hash functions

use digest::{generic_array::GenericArray, Digest};
use std::{iter::Iterator, mem};

/// The hash function used in PBMX
pub type Hash = ripemd160::Ripemd160;

/// Creates an iterator produces a sequence of applications of a hash function
pub fn hash_iter(h: Hash) -> HashIter {
    HashIter::new(h)
}

/// An iterator that produces a sequence of applications of a hash function
pub struct HashIter {
    h: Hash,
    r: HashOutput,
}

type HashOutput = GenericArray<u8, <Hash as Digest>::OutputSize>;

impl HashIter {
    fn new(mut h: Hash) -> HashIter {
        HashIter {
            r: h.result_reset(),
            h,
        }
    }
}

impl Iterator for HashIter {
    type Item = HashOutput;

    fn next(&mut self) -> Option<Self::Item> {
        self.h.input(&self.r);
        Some(mem::replace(&mut self.r, self.h.result_reset()))
    }
}
