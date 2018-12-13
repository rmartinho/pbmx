use crate::rand::thread_rng;

use rug::integer::IsPrime;
use rug::{Assign, Integer};

/// Generates a random (probable) prime number with the given `bits` that passes the given `test`.
///
/// The probability of a composite number being generated is less than 4^-iterations.
pub fn generate_prime_with<F>(bits: u32, iterations: u32, test: F) -> Integer
where
    F: Fn(&Integer) -> bool,
{
    let mut rng = thread_rng();
    let mut n = Integer::new();
    loop {
        n.assign(Integer::random_bits(bits, &mut rng));
        n.set_bit(0, true);
        n.set_bit(bits - 1, true);
        if test(&n) && n.is_probably_prime(iterations) != IsPrime::No {
            return n;
        }
    }
}

/// Generates a number below `n` that is co-prime with `n`.
pub fn generate_coprime_below(n: &Integer) -> Integer {
    let mut rng = thread_rng();
    let mut i = Integer::new();
    let mut gcd = Integer::new();
    loop {
        i.assign(n.random_below_ref(&mut rng));
        gcd.assign(i.gcd_ref(n));
        if gcd == 1 {
            break;
        }
    }
    i
}

#[cfg(test)]
mod test {
    use super::*;
    use rug::integer::IsPrime;

    #[test]
    pub fn generate_prime_with_produces_prime_with_property() {
        let prime = generate_prime_with(1024, 64, |p| p.is_congruent_u(3, 4));

        assert!(prime.is_congruent_u(3, 4));
        assert_ne!(prime.is_probably_prime(64), IsPrime::No);
    }

    #[test]
    pub fn generate_coprime_below_produces_coprime() {
        let n = Integer::from(1209302942);
        let coprime = generate_coprime_below(&n);

        assert_eq!(coprime.gcd(&n), 1);
    }
}
