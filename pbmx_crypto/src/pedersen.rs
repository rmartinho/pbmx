//! Pedersen commitment scheme

use crate::{
    num::{fpowm, Modulo},
    schnorr,
};
use rand::{thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};

/// The Pedersen commitment scheme
#[derive(Serialize)]
pub struct CommitmentScheme {
    group: schnorr::Group,
    h: Integer,
    g: Vec<Integer>,
}

impl CommitmentScheme {
    unsafe fn new_unchecked(group: schnorr::Group, h: Integer, g: Vec<Integer>) -> Self {
        for g in g.iter() {
            fpowm::precompute(g, group.bits(), group.modulus()).unwrap();
        }
        Self { group, h, g }
    }

    /// Creates a new commitment scheme from the given parameters
    pub fn new(group: schnorr::Group, h: Integer, n: usize) -> Option<Self> {
        let mut rng = thread_rng();
        let g = rng.sample_iter(&group).take(n).collect();
        // SAFE: the value is checked before returning
        unsafe { Self::new_unchecked(group, h, g) }.validate()
    }

    /// Creates a commitment to a given message.
    ///
    /// The first return value is the commitment, and the second is the
    /// randomizer.
    pub fn commit_to(&self, m: &[Integer]) -> (Integer, Integer) {
        assert!(m.len() == self.g.len());

        let r = thread_rng().sample(&Modulo(self.group.order()));
        let c = self.commit_by(m, &r);
        (c, r)
    }

    /// Validates that a commitment is well-formed, i.e. an element of the group
    pub fn is_valid(&self, c: &Integer) -> bool {
        self.group.has_element(c)
    }

    /// Verifies a commitment to a given message.
    pub fn open(&self, m: &[Integer], c: &Integer, r: &Integer) -> bool {
        assert!(m.len() == self.g.len());

        if r >= self.group.order() {
            return false;
        }

        let c1 = self.commit_by(m, r);
        *c == c1
    }

    fn commit_by(&self, m: &[Integer], r: &Integer) -> Integer {
        assert!(m.len() == self.g.len());
        assert!(r < self.group.order());

        let p = self.group.modulus();

        let gm = self
            .g
            .iter()
            .zip(m)
            .map(|(g, m)| fpowm::pow_mod(g, m, p).unwrap())
            .fold(Integer::from(1), |acc, gm| acc * gm % p);

        let hr = fpowm::pow_mod(&self.h, r, p).unwrap();
        gm * hr % p
    }

    fn validate(self) -> Option<Self> {
        let pm1 = Integer::from(self.group.modulus() - 1);

        if !self.group.has_element(&self.h) {
            return None;
        }
        if self.h <= 1 || self.h == pm1 {
            return None;
        }

        for i in 0..self.g.len() {
            if !self.group.has_element(&self.g[i]) {
                return None;
            }

            if self.g[i] <= 1 || self.g[i] == pm1 || self.g[i] == self.h {
                return None;
            }

            for j in 0..i {
                if self.g[i] == self.g[j] {
                    return None;
                }
            }
        }

        Some(self)
    }
}

impl<'de> Deserialize<'de> for CommitmentScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { CommitmentSchemeRaw::deserialize(deserializer)?.into() }
            .validate()
            .ok_or_else(|| de::Error::custom("invalid Pedersen commitment scheme parameters"))
    }
}

#[derive(Deserialize)]
struct CommitmentSchemeRaw {
    group: schnorr::Group,
    h: Integer,
    g: Vec<Integer>,
}

impl CommitmentSchemeRaw {
    unsafe fn into(self) -> CommitmentScheme {
        CommitmentScheme::new_unchecked(self.group, self.h, self.g)
    }
}
// TODO(#4) macro for deserializing with invariants

derive_base64_conversions!(CommitmentScheme);

#[cfg(test)]
mod test {
    use super::CommitmentScheme;
    use crate::schnorr;
    use rand::{thread_rng, Rng};
    use rug::Integer;
    use std::str::FromStr;

    #[test]
    fn pedersen_scheme_commitments_agree_with_validation() {
        let mut rng = thread_rng();
        let dist = schnorr::Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let h = rng.sample(&group);
        let com = CommitmentScheme::new(group, h, 3).unwrap();

        let m = [Integer::from(2), Integer::from(3), Integer::from(4)];
        let (c, r) = com.commit_to(&m);
        assert!(
            com.is_valid(&c),
            "commitment is not valid\n\tc = {}\n\tgroup = {:?}\n\th = {}\n\tg = {:?}",
            c,
            com.group,
            com.h,
            com.g
        );
        let ok = com.open(&m, &c, &r);
        assert!(
            ok,
            "opening failed\n\tm = {:?}\n\tc = {}\n\tr = {}\n\tgroup = {:?}\n\th = {}\n\tg = {:?}",
            m, c, r, com.group, com.h, com.g
        );

        // find small non-element
        let mut x = Integer::from(1);
        loop {
            let xq = x
                .clone()
                .pow_mod(com.group.order(), com.group.modulus())
                .unwrap();
            if xq != 1 {
                break;
            }
            x += 1;
        }
        assert!(
            !com.is_valid(&x),
            "non-commitment is valid\n\tc = {}\n\tgroup = {:?}\n\th = {}\n\tg = {:?}",
            x,
            com.group,
            com.h,
            com.g
        );

        let fake = [Integer::from(2), Integer::from(4), Integer::from(3)];
        let (c1, r1) = com.commit_to(&fake);
        assert!(
            com.is_valid(&c1),
            "commitment is not valid\n\tc = {}\n\tgroup = {:?}\n\th = {}\n\tg = {:?}",
            c1,
            com.group,
            com.h,
            com.g
        );
        let ok = com.open(&m, &c1, &r1);
        assert!(!ok, "bad opening is not detected\n\tm = {:?}\n\tc = {}\n\tr = {}\n\tgroup = {:?}\n\th = {}\n\tg = {:?}", m, c1, r1, com.group, com.h, com.g);
    }

    #[test]
    fn pedersen_scheme_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let dist = schnorr::Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let h = rng.sample(&group);
        let original = CommitmentScheme::new(group, h, 3).unwrap();
        println!("scheme = {}", original);

        let exported = original.to_string();

        let recovered = CommitmentScheme::from_str(&exported).unwrap();

        assert_eq!(original.group, recovered.group);
        assert_eq!(original.h, recovered.h);
        assert_eq!(original.g, recovered.g);
    }
}
