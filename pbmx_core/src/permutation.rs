//! Permutation-related utilities

use core::ops::Deref;
use rand::{distributions::Distribution, seq::SliceRandom, Rng};

/// A permutation
pub struct Permutation(Vec<usize>);

impl Deref for Permutation {
    type Target = [usize];

    fn deref(&self) -> &[usize] {
        &self.0
    }
}

/// A distribution that produces shuffle permutations of the given size
pub struct Shuffles(pub usize);

/// A distribution that produces cyclic shift permutations of the given size
pub struct Shifts(pub usize);

impl Distribution<Permutation> for Shuffles {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Permutation {
        let mut v = Vec::with_capacity(self.0);
        v.extend(0..self.0);

        v.shuffle(rng);
        Permutation(v)
    }
}

impl Distribution<Permutation> for Shifts {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Permutation {
        let c: usize = rng.gen();
        let v = (0..self.0).map(|i| (i + c) % self.0).collect();
        Permutation(v)
    }
}
