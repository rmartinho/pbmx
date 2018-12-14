use rug::Integer;
use std::{cmp::min as at_most, iter};

pub struct FastPowModTable {
    table: Vec<Integer>,
    modulus: Integer,
}

impl FastPowModTable {
    pub fn new(bits: u32, modulus: &Integer, seed: &Integer) -> FastPowModTable {
        let mut table = Vec::new();
        let size = at_most(MAX_TABLE_SIZE, bits as _);
        table.reserve_exact(size);

        table.push(seed.clone());
        table.extend(
            iter::unfold(seed.clone(), |g| {
                g.square_mut();
                *g %= modulus;
                Some(g.clone())
            })
            .take(size),
        );
        FastPowModTable { table, modulus: modulus.clone() }
    }

    pub fn pow_mod(&self, exponent: &Integer) -> Option<Integer> {
        let exp_abs = exponent.clone().abs();
        let bits = exp_abs.significant_bits() as _;

        if bits <= self.table.len() {
            let mut r = Integer::from(1);
            for i in 0..bits {
                if exp_abs.get_bit(i as _) {
                    r *= &self.table[i];
                    r %= &self.modulus;
                }
            }
            if exponent < &0 {
                r.invert_mut(&self.modulus).ok()?
            }
            Some(r)
        } else {
            None
        }
    }
}

const MAX_TABLE_SIZE: usize = 2048;
