use rand::{distributions::Distribution, Rng};
use rug::{
    rand::{RandGen, RandState},
    Integer,
};

/// A distribution that produces Integers below n
pub struct Modulo(pub Integer);

impl Distribution<Integer> for Modulo {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut wrapper = RandGenWrapper(rng);
        let mut state = RandState::new_custom(&mut wrapper);
        self.0.random_below_ref(&mut state).into()
    }
}
// TODO(#1) Distributions for incomplete types

/// A distribution that produces Integers with n bits
pub struct Bits(pub u32);

impl Distribution<Integer> for Bits {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut wrapper = RandGenWrapper(rng);
        let mut state = RandState::new_custom(&mut wrapper);
        Integer::random_bits(self.0, &mut state).into()
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
