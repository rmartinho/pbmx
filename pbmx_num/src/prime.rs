use crate::rand::{Bits, Modulo};
use rand::{distributions::Distribution, Rng};
use rug::{integer::IsPrime, Assign, Integer};

/// A distribution that produces (probable) prime [Integer]s with the given
/// number of bits.
///
/// The probability of a composite number being generated is less than
/// 4^-iterations.
pub struct Primes<'a> {
    bits: u32,
    iterations: u32,
    test: &'a dyn Fn(&Integer) -> bool,
}

impl<'a> Primes<'a> {
    /// Creates a new [Primes] distribution for primes with the given number of
    /// bits and Miller-Rabin iterations
    pub fn new(bits: u32, iterations: u32) -> Primes<'static> {
        Primes { bits, iterations, test: &Primes::no_test }
    }

    /// Creates a new [Primes] distribution for primes with the given number of
    /// bits and Miller-Rabin iterations, and additionally passing the given
    /// test
    pub fn with_test(bits: u32, iterations: u32, test: &'a dyn Fn(&Integer) -> bool) -> Primes<'a> {
        Primes { bits, iterations, test }
    }

    fn no_test(_: &Integer) -> bool {
        true
    }
}

impl<'a> Distribution<Integer> for Primes<'a> {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut n = Integer::new();
        loop {
            n.assign(rng.sample(&Bits(self.bits)));
            n.set_bit(0, true);
            n.set_bit(self.bits - 1, true);
            if (self.test)(&n) && n.is_probably_prime(self.iterations) != IsPrime::No {
                return n;
            }
        }
    }
}

/// A distribution that produces [Integer]s co-prime to (and less than) the
/// given value.
pub struct Coprimes<'a>(pub &'a Integer);

impl<'a> Distribution<Integer> for Coprimes<'a> {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut n = Integer::new();
        let mut div = Integer::new();
        loop {
            n.assign(rng.sample(&Modulo(self.0)));
            div.assign(n.gcd_ref(self.0));
            if div == 1 {
                return n;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Coprimes, Primes};
    use rand::{thread_rng, Rng};
    use rug::{integer::IsPrime, Integer};

    #[test]
    fn primes_produces_primes_with_property() {
        let dist = Primes::with_test(1024, 64, &|p| p.is_congruent_u(3, 4));
        let prime = thread_rng().sample(&dist);

        assert!(prime.is_congruent_u(3, 4));
        assert_ne!(prime.is_probably_prime(64), IsPrime::No);
    }

    #[test]
    fn coprimes_produces_coprimes() {
        let n = Integer::from(1209302942);
        let dist = Coprimes(&n);
        let coprime = thread_rng().sample(&dist);

        assert_eq!(coprime.gcd(&n), 1);
    }
}
