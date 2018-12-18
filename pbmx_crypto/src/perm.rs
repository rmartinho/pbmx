//! Permutation-related utilities

use crate::error::Error;
use rand::{distributions::Distribution, seq::SliceRandom, Rng};
use std::{convert::TryFrom, ops::Deref};

/// A permutation
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permutation(Vec<usize>);

impl Permutation {
    /// Creates a new identity permutation
    pub fn identity(n: usize) -> Self {
        let v = (0..n).collect();
        Self(v)
    }

    /// Creates a new cyclic shift permutation
    pub fn shift(n: usize, c: usize) -> Self {
        let v = (0..n).map(|i| (i + c) % n).collect();
        Self(v)
    }

    /// Creates a permutation equivalent to applying this permutation after
    /// another
    pub fn after(&self, other: &Self) -> Self {
        assert!(self.len() == other.len());

        let mut v = Vec::with_capacity(self.len());
        for i in 0..self.len() {
            v.push(other[self[i]]);
        }
        Self(v)
    }

    /// Creates a permutation equivalent to undoing this permutation
    pub fn inverse(&self) -> Self {
        let mut v = Vec::new();
        v.resize(self.len(), 0);
        for i in 0..self.len() {
            v[self[i]] = i;
        }
        Self(v)
    }
}

impl Deref for Permutation {
    type Target = [usize];

    fn deref(&self) -> &[usize] {
        &self.0
    }
}

impl From<Permutation> for Vec<usize> {
    fn from(p: Permutation) -> Self {
        p.0
    }
}

impl TryFrom<Vec<usize>> for Permutation {
    type Error = Error;

    fn try_from(v: Vec<usize>) -> Result<Self, Self::Error> {
        let mut o = v.clone();
        o.sort();
        if o.into_iter().eq(0..v.len()) {
            Ok(Self(v))
        } else {
            Err(Error::NonPermutation)
        }
    }
}

/// A distribution that produces shuffle permutations of the given size
pub struct Shuffles(pub usize);

/// A distribution that produces cyclic shift permutations of the given size
pub struct Shifts(pub usize);

impl Distribution<Permutation> for Shuffles {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Permutation {
        let mut v: Vec<_> = (0..self.0).collect();
        v.shuffle(rng);
        Permutation(v)
    }
}

impl Distribution<Permutation> for Shifts {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Permutation {
        let c = rng.gen();
        Permutation::shift(self.0, c)
    }
}
