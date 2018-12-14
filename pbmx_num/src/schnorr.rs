use crate::{
    prime::Primes,
    rand::{BitsExact, Modulo},
};
use rand::{distributions::Distribution, Rng};
use rug::{integer::IsPrime, Assign, Integer};

use serde::{de, Deserialize, Deserializer};

/// A distribution that produces Schnorr groups from primes *p*, *q* with the
/// given bit sizes.
pub struct Schnorr {
    /// The number of bits in the field
    pub field_bits: u32,
    /// The number of bits in the subgroup
    pub group_bits: u32,
    /// The number of Miller-Rabin iterations for primality tests
    pub iterations: u32,
}

impl Distribution<SchnorrGroup> for Schnorr {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SchnorrGroup {
        let q = rng.sample(&Primes::new(self.group_bits, self.iterations));

        let mut k;
        let mut p = Integer::new();
        let mut div = Integer::new();
        loop {
            k = rng.sample(&BitsExact(self.field_bits - self.group_bits));
            if k.is_odd() {
                k += 1;
            }

            p.assign(&q * &k);
            p += 1;

            div.assign(k.gcd_ref(&q));
            if div == 1
                && p.significant_bits() == self.field_bits
                && p.is_probably_prime(self.iterations) != IsPrime::No
            {
                break;
            }
        }

        let mut d;
        let pm1 = Integer::from(&p - 1);
        let mut g = Integer::new();
        loop {
            d = rng.sample(&Modulo(&p));
            g.assign(d.pow_mod_ref(&k, &p).unwrap());
            if g > 1 && g < pm1 {
                break;
            }
        }

        // SAFE: we just generated these values properly
        unsafe { SchnorrGroup::new_unchecked(p, q, k, g) }
    }
}

/// A Schnorr group.
///
/// See the wikipedia page on [Schnorr groups](https://en.wikipedia.org/wiki/Schnorr_group).
#[derive(Serialize)]
pub struct SchnorrGroup {
    p: Integer,
    q: Integer,
    k: Integer,
    g: Integer,
}

impl SchnorrGroup {
    unsafe fn new_unchecked(p: Integer, q: Integer, k: Integer, g: Integer) -> SchnorrGroup {
        Self { p, q, k, g }
    }

    fn check(self) -> Option<SchnorrGroup> {
        let mut x = Integer::from(&self.q * &self.k);
        x += 1;
        if self.p != x {
            return None;
        }

        if self.p.is_probably_prime(SCHNORR_MILLER_RABIN_ITERATIONS) == IsPrime::No
            || self.q.is_probably_prime(SCHNORR_MILLER_RABIN_ITERATIONS) == IsPrime::No
        {
            return None;
        }

        x.assign(self.q.gcd_ref(&self.k));
        if x != 1 {
            return None;
        }

        x.assign(&self.p - 1);
        if self.g <= 1 || self.g == x {
            return None;
        }

        x.assign(self.g.pow_mod_ref(&self.q, &self.p).unwrap()); // TODO powmodtable
        if x != 1 {
            return None;
        }

        Some(self)
    }

    /// Creates a new group from the given parameters
    pub fn new(p: Integer, q: Integer, k: Integer, g: Integer) -> Option<SchnorrGroup> {
        Self { p, q, k, g }.check()
    }

    /// Gets the modulus of the group (aka *p*)
    pub fn modulus(&self) -> &Integer {
        &self.p
    }

    /// Gets the order of the group (aka *q*)
    pub fn order(&self) -> &Integer {
        &self.q
    }

    /// Gets the factor between the modulus and the order of the group (aka *k*)
    pub fn factor(&self) -> &Integer {
        &self.k
    }

    /// Gets the generator of the group (aka *g*)
    pub fn generator(&self) -> &Integer {
        &self.g
    }
}

impl<'de> Deserialize<'de> for SchnorrGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SchnorrGroupRaw::deserialize(deserializer)?
            .check()
            .ok_or(de::Error::custom("invalid Schnorr group parameters"))
    }
}

#[derive(Deserialize)]
#[serde(remote = "SchnorrGroup")]
struct SchnorrGroupRaw {
    p: Integer,
    q: Integer,
    k: Integer,
    g: Integer,
}

const SCHNORR_MILLER_RABIN_ITERATIONS: u32 = 64;

#[cfg(test)]
mod test {
    use super::Schnorr;
    use rand::{thread_rng, Rng};
    use rug::integer::IsPrime;

    #[test]
    fn schnorr_produces_schnorr_groups() {
        let dist = Schnorr { field_bits: 2048, group_bits: 1024, iterations: 64 };
        let schnorr = thread_rng().sample(&dist);

        assert_eq!(schnorr.p.significant_bits(), 2048);
        assert_ne!(schnorr.p.is_probably_prime(64), IsPrime::No);
        assert_eq!(schnorr.q.significant_bits(), 1024);
        assert_ne!(schnorr.q.is_probably_prime(64), IsPrime::No);
        assert_eq!(schnorr.p, schnorr.q.clone() * schnorr.k + 1);
    }
}
