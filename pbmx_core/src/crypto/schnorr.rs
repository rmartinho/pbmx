use crate::num::{
    fpowm::FastPowModTable,
    integer::{BitsExact, Modulo},
    prime::Primes,
};
use rand::{distributions::Distribution, Rng};
use rug::{integer::IsPrime, Assign, Integer};
use serde::{de, Deserialize, Deserializer};

/// A Schnorr group.
///
/// See the wikipedia page on [Schnorr groups](https://en.wikipedia.org/wiki/Schnorr_group).
#[derive(Clone, Debug, Serialize)]
pub struct SchnorrGroup {
    p: Integer,
    q: Integer,
    k: Integer,
    g: Integer,

    #[serde(skip)]
    pub(super) fpowm: FastPowModTable,
}

impl SchnorrGroup {
    unsafe fn new_unchecked(p: Integer, q: Integer, k: Integer, g: Integer) -> Self {
        Self {
            fpowm: FastPowModTable::new(&g, q.significant_bits(), &p),
            p,
            q,
            k,
            g,
        }
    }

    /// Creates a new group from the given parameters
    pub fn new(p: Integer, q: Integer, k: Integer, g: Integer) -> Option<Self> {
        // SAFE: the value is checked before returning
        unsafe { Self::new_unchecked(p, q, k, g) }.validate()
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

    /// Tests whether a given number is an element of the group
    pub fn has_element(&self, e: &Integer) -> bool {
        if *e <= 0 || *e >= self.p {
            return false;
        }

        let x = Integer::from(e.pow_mod_ref(&self.q, &self.p).unwrap());
        x == 1
    }

    /// Retrieves the i-th element of the group
    pub fn element(&self, i: &Integer) -> Integer {
        self.fpowm.pow_mod(i).unwrap()
    }

    fn validate(self) -> Option<Self> {
        let mut x = Integer::from(&self.q * &self.k);
        x += 1;
        if self.p != x {
            return None;
        }

        if self.p.is_probably_prime(MILLER_RABIN_ITERATIONS) == IsPrime::No
            || self.q.is_probably_prime(MILLER_RABIN_ITERATIONS) == IsPrime::No
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

        x = self.fpowm.pow_mod(&self.q).unwrap();
        if x != 1 {
            return None;
        }

        Some(self)
    }
}

impl PartialEq for SchnorrGroup {
    fn eq(&self, rhs: &Self) -> bool {
        self.p == rhs.p && self.q == rhs.q && self.k == rhs.k && self.g == rhs.g
    }
}

impl Eq for SchnorrGroup {}

impl Distribution<Integer> for SchnorrGroup {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Integer {
        let mut i: Integer;
        loop {
            i = rng.sample(&Modulo(&self.q));
            if i != 0 {
                break;
            }
        }
        self.fpowm.pow_mod(&i).unwrap()
    }
}

impl<'de> Deserialize<'de> for SchnorrGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { SchnorrGroupRaw::deserialize(deserializer)?.into() }
            .validate()
            .ok_or(de::Error::custom("invalid Schnorr group parameters"))
    }
}

#[derive(Deserialize)]
struct SchnorrGroupRaw {
    p: Integer,
    q: Integer,
    k: Integer,
    g: Integer,
}

impl SchnorrGroupRaw {
    unsafe fn into(self) -> SchnorrGroup {
        SchnorrGroup::new_unchecked(self.p, self.q, self.k, self.g)
    }
}

/// A distribution that produces Schnorr groups from primes *p*, *q* with the
/// given bit sizes.
#[derive(Clone, Debug)]
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

derive_base64_conversions!(SchnorrGroup);

const MILLER_RABIN_ITERATIONS: u32 = 64;

#[cfg(test)]
mod test {
    use super::{Schnorr, SchnorrGroup, MILLER_RABIN_ITERATIONS};
    use crate::num::integer::Bits;
    use rand::{thread_rng, Rng};
    use rug::{integer::IsPrime, Integer};
    use std::str::FromStr;

    #[test]
    fn schnorr_produces_schnorr_groups() {
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: MILLER_RABIN_ITERATIONS,
        };
        let schnorr = thread_rng().sample(&dist);

        assert_eq!(schnorr.p.significant_bits(), 2048);
        assert_ne!(schnorr.p.is_probably_prime(64), IsPrime::No);
        assert_eq!(schnorr.q.significant_bits(), 1024);
        assert_ne!(schnorr.q.is_probably_prime(64), IsPrime::No);
        assert_eq!(schnorr.p, schnorr.q.clone() * schnorr.k + 1);
    }

    #[test]
    fn schnorr_group_element_produces_elements_correctly() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: MILLER_RABIN_ITERATIONS,
        };
        let schnorr = rng.sample(&dist);

        let i = rng.sample(&Bits(128));
        let gi = Integer::from(
            schnorr
                .generator()
                .pow_mod_ref(&i, schnorr.modulus())
                .unwrap(),
        );

        let element = schnorr.element(&i);

        assert_eq!(element, gi);
    }

    #[test]
    fn schnorr_group_has_element_detects_elements_correctly() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: MILLER_RABIN_ITERATIONS,
        };
        let schnorr = rng.sample(&dist);

        let i = rng.sample(&Bits(128));
        let gi = Integer::from(
            schnorr
                .generator()
                .pow_mod_ref(&i, schnorr.modulus())
                .unwrap(),
        );

        assert!(
            schnorr.has_element(&gi),
            "element was not detected\n\tgenerator = {}\n\tmodulus = {}\n\telement = {}",
            schnorr.generator(),
            schnorr.modulus(),
            gi
        );

        // find small non-element
        let mut x = Integer::from(1);
        loop {
            let xq = x
                .clone()
                .pow_mod(schnorr.order(), schnorr.modulus())
                .unwrap();
            if xq != 1 {
                break;
            }
            x += 1;
        }

        assert!(
            !schnorr.has_element(&x),
            "element was not detected\n\tgenerator = {}\n\tmodulus = {}\n\telement = {}",
            schnorr.generator(),
            schnorr.modulus(),
            gi
        );
    }

    #[test]
    fn schnorr_group_roundtrips_via_base64() {
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: MILLER_RABIN_ITERATIONS,
        };
        let original = thread_rng().sample(&dist);
        println!("group = {}", original);

        let exported = original.to_string();

        let recovered = SchnorrGroup::from_str(&exported).unwrap();

        assert_eq!(original.p, recovered.p);
        assert_eq!(original.q, recovered.q);
        assert_eq!(original.k, recovered.k);
        assert_eq!(original.g, recovered.g);
        assert_eq!(original.fpowm, recovered.fpowm);
    }
}
