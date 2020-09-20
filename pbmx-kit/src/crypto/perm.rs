//! Permutation-related utilities

use crate::error::InvalidPermutationError;
use rand::{distributions::Distribution, seq::SliceRandom, Rng};
use std::{convert::TryFrom, ops::Deref};

/// A permutation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permutation(Vec<usize>);

impl Permutation {
    /// Creates a new identity permutation
    pub fn identity(n: usize) -> Self {
        let v = (0..n).collect();
        Self(v)
    }

    /// Creates a new cyclic shift permutation
    pub fn shift(n: usize, c: usize) -> Self {
        let v = (0..n).map(|i| (i + n - c) % n).collect();
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

    /// Applies a permutation to a slice
    pub fn apply_to<T>(&self, slice: &mut [T]) {
        let mut placed = Vec::new();
        placed.resize(self.len(), false);

        while let Some(start) = placed.iter().position(|&b| !b) {
            let mut i = start;
            loop {
                let p = self[i];
                if p == start {
                    placed[i] = true;
                    break;
                }
                slice.swap(i, p);
                placed[i] = true;
                i = p;
            }
        }
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
    type Error = InvalidPermutationError;

    fn try_from(v: Vec<usize>) -> Result<Self, Self::Error> {
        let mut o = v.clone();
        o.sort();
        if o.into_iter().ne(0..v.len()) {
            return Err(InvalidPermutationError);
        };

        Ok(Self(v))
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
        let c = rng.gen_range(0, self.0);
        Permutation::shift(self.0, c)
    }
}

#[cfg(test)]
mod tests {
    use super::{Permutation, Shifts, Shuffles};
    use rand::{thread_rng, Rng};
    use std::convert::TryFrom;

    #[test]
    fn permutation_identity_is_correct() {
        let mut expected = Vec::new();
        expected.extend(0..10);

        let p = Permutation::identity(10);
        assert_eq!(p.0, expected);
    }

    #[test]
    fn permutation_shifts_are_generated_correctly() {
        let mut expected = Vec::new();
        expected.extend(7..10);
        expected.extend(0..7);

        let p = Permutation::shift(10, 3);
        assert_eq!(p.0, expected);
    }

    #[test]
    fn permutation_random_shifts_are_generated_correctly() {
        let mut expected = Vec::new();
        expected.extend(0..10);

        let mut p = thread_rng().sample(&Shifts(10));
        let slice = p.0.as_mut_slice();
        let p = slice.iter().position(|&x| x == 0).unwrap();
        let (last, first) = slice.split_at(p);
        let mut v = Vec::new();
        v.extend_from_slice(first);
        v.extend_from_slice(last);

        assert_eq!(v, expected);
    }

    #[test]
    fn permutation_from_vector_accepts_only_valid_permutations() {
        let valid = vec![3, 2, 4, 6, 9, 1, 7, 5, 8, 0];
        let invalid1 = vec![3, 2, 4, 6, 3, 1, 7, 5, 8, 0];
        let invalid2 = vec![3, 2, 4, 6, 9, 1, 7, 5, 8, 10];

        let r = Permutation::try_from(valid);
        assert!(r.is_ok());

        let r = Permutation::try_from(invalid1);
        assert!(r.is_err());
        let r = Permutation::try_from(invalid2);
        assert!(r.is_err());
    }

    #[test]
    fn permutation_random_shuffles_are_generated_correctly() {
        let mut expected = Vec::new();
        expected.extend(0..10);

        let mut p = thread_rng().sample(&Shuffles(10));
        p.0.sort();

        assert_eq!(p.0, expected);
    }

    #[test]
    fn permutation_inverse_is_correct() {
        let original = Permutation::try_from(vec![3, 2, 4, 6, 9, 1, 7, 5, 8, 0]).unwrap();
        let expected = Permutation::try_from(vec![9, 5, 1, 0, 2, 7, 3, 6, 8, 4]).unwrap();

        let inverted = original.inverse();

        assert_eq!(expected, inverted);
    }

    #[test]
    fn permutation_double_inverse_is_identity() {
        let original = Permutation::try_from(vec![3, 2, 4, 6, 9, 1, 7, 5, 8, 0]).unwrap();
        let inverted2 = original.inverse().inverse();

        assert_eq!(original, inverted2);
    }

    #[test]
    fn permutation_combines_correctly() {
        let first = Permutation::try_from(vec![3, 2, 4, 6, 9, 1, 7, 5, 8, 0]).unwrap();
        let second = Permutation::try_from(vec![3, 5, 4, 6, 0, 8, 2, 7, 9, 1]).unwrap();
        let expected = Permutation::try_from(vec![6, 1, 9, 7, 3, 8, 4, 5, 0, 2]).unwrap();

        let combined = second.after(&first);

        assert_eq!(expected, combined);
    }

    #[test]
    fn permutation_mixes_correctly() {
        let mut v = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
        let p = Permutation::try_from(vec![3, 2, 4, 6, 9, 1, 7, 5, 8, 0]).unwrap();
        let expected = vec!["d", "c", "e", "g", "j", "b", "h", "f", "i", "a"];

        p.apply_to(&mut v);

        assert_eq!(expected, v);
    }
}
