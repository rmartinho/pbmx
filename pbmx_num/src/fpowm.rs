use rug::Integer;
use std::iter;

/// Precomputed fast modular exponentiation table
#[derive(Clone, Debug)]
pub struct FastPowModTable {
    table: Vec<Integer>,
    modulus: Integer,
}

impl FastPowModTable {
    /// Creates a new table supporting exponents with up to the given number of
    /// bits, for the given modulus and base.
    pub fn new(bits: u32, modulus: &Integer, base: &Integer) -> FastPowModTable {
        let mut table = Vec::new();
        table.reserve_exact(bits as _);

        table.push(base.clone());
        table.extend(
            iter::unfold(base.clone(), |g| {
                g.square_mut();
                *g %= modulus;
                Some(g.clone())
            })
            .take(bits as _),
        );
        FastPowModTable {
            table,
            modulus: modulus.clone(),
        }
    }

    /// Performs a fast modular exponentiation
    pub fn pow_mod(&self, exponent: &Integer) -> Option<Integer> {
        let exp_abs = exponent.clone().abs();
        let bits = exp_abs.significant_bits() as _;

        if bits <= self.table.len() {
            let mut r = Integer::from(1);
            for i in 0..bits {
                // TODO(#2) timing attack protections
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
