use crate::{
    crypto::schnorr::SchnorrGroup,
    num::{fpowm::FastPowModTable, integer::Modulo},
};
use rand::{thread_rng, Rng};
use rug::Integer;
use serde::{de, Deserialize, Deserializer};

/// The Pedersen commitment scheme
#[derive(Serialize)]
pub struct PedersenScheme {
    group: SchnorrGroup,
    h: Integer,
    g: Vec<Integer>,

    #[serde(skip)]
    fpowm_g: Vec<FastPowModTable>,

    #[serde(skip)]
    fpowm_h: FastPowModTable,
}

impl PedersenScheme {
    unsafe fn new_unchecked(group: SchnorrGroup, h: Integer, g: Vec<Integer>) -> Self {
        let p = group.modulus();
        let q = group.order();
        Self {
            fpowm_h: FastPowModTable::new(&h, q.significant_bits(), p),
            fpowm_g: g
                .iter()
                .map(|g| FastPowModTable::new(g, q.significant_bits(), p))
                .collect(),
            group,
            h,
            g,
        }
    }

    /// Creates a new commitment scheme from the given parameters
    pub fn new(group: SchnorrGroup, h: Integer, n: usize) -> Option<Self> {
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

        let c1 = self.commit_by(m, r);
        *c == c1
    }

    fn commit_by(&self, m: &[Integer], r: &Integer) -> Integer {
        assert!(m.len() == self.g.len());

        let p = self.group.modulus();

        let gm = self
            .fpowm_g
            .iter()
            .zip(m)
            .map(|(fpowm, m)| fpowm.pow_mod(m).unwrap())
            .fold(Integer::from(1), |acc, gm| acc * gm % p);

        let hr = Integer::from(self.fpowm_h.pow_mod(r).unwrap());
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

impl<'de> Deserialize<'de> for PedersenScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // SAFE: we explicit validate the values before returning
        unsafe { PedersenSchemeRaw::deserialize(deserializer)?.into() }
            .validate()
            .ok_or(de::Error::custom(
                "invalid Pedersen commitment scheme parameters",
            ))
    }
}

#[derive(Deserialize)]
struct PedersenSchemeRaw {
    group: SchnorrGroup,
    h: Integer,
    g: Vec<Integer>,
}

impl PedersenSchemeRaw {
    unsafe fn into(self) -> PedersenScheme {
        PedersenScheme::new_unchecked(self.group, self.h, self.g)
    }
}
