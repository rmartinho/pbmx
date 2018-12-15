use rand::{distributions::Distribution, Rng};
use rug::{
    rand::{RandGen, RandState},
    Integer,
};

/// A distribution that produces [Integer]s below a certain value.
#[derive(Clone, Debug)]
pub struct Modulo<'a>(pub &'a Integer);

impl<'a> Distribution<Integer> for Modulo<'a> {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut wrapper = RandGenWrapper(rng);
        let mut state = RandState::new_custom(&mut wrapper);
        self.0.random_below_ref(&mut state).into()
    }
}
// TODO(#1) Distributions for incomplete types

/// A distribution that produces [Integer]s up to a certain number of bits.
#[derive(Clone, Debug)]
pub struct Bits(pub u32);

impl Distribution<Integer> for Bits {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut wrapper = RandGenWrapper(rng);
        let mut state = RandState::new_custom(&mut wrapper);
        Integer::random_bits(self.0, &mut state).into()
    }
}

/// A distribution that produces [Integer]s with an exact number of bits.
#[derive(Clone, Debug)]
pub struct BitsExact(pub u32);

impl Distribution<Integer> for BitsExact {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut n = rng.sample(&Bits(self.0));
        n.set_bit(self.0 - 1, true);
        n
    }
}

struct RandGenWrapper<'a, R: ?Sized>(&'a mut R);

// SAFE: not really Send, but this won't be used across threads (rug is stupid)
unsafe impl<'a, R: ?Sized> Send for RandGenWrapper<'a, R> {}
// SAFE: not really Sync, but this won't be used across threads (rug is stupid)
unsafe impl<'a, R: ?Sized> Sync for RandGenWrapper<'a, R> {}

impl<'a, R> RandGen for RandGenWrapper<'a, R>
where
    R: Rng + ?Sized,
{
    fn gen(&mut self) -> u32 {
        self.0.gen()
    }
}
