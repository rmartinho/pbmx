use crate::{error::Error, Result};
use rug::Integer;
use std::{collections::HashMap, iter, sync::Mutex};

lazy_static! {
    static ref FPOWM_TABLES: Mutex<HashMap<(Integer, Integer), FastPowModTable>> =
        Mutex::new(HashMap::new());
}

/// Precomputes a fast modular exponentiation table
pub fn precompute(base: &Integer, bits: u32, modulus: &Integer) -> Result<()> {
    let key = (base.clone(), modulus.clone());
    match FPOWM_TABLES.lock() {
        Ok(mut cache) => {
            cache
                .entry(key)
                .or_insert_with(|| FastPowModTable::new(base, bits, modulus));
            Ok(())
        }
        _ => Err(Error::FpowmPrecomputeFailure),
    }
}

/// Computes a modular exponentiation using precomputed tables if possible
pub fn pow_mod(b: &Integer, e: &Integer, m: &Integer) -> Option<Integer> {
    match FPOWM_TABLES.lock() {
        Ok(cache) => {
            let key = (b.clone(), m.clone());
            match cache.get(&key) {
                Some(fpowm) => fpowm.pow_mod(e),
                None => key.0.pow_mod(e, m).ok(),
            }
        }
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FastPowModTable {
    table: Vec<Integer>,
    modulus: Integer,
}

impl FastPowModTable {
    fn new(base: &Integer, bits: u32, modulus: &Integer) -> FastPowModTable {
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

    fn pow_mod(&self, exponent: &Integer) -> Option<Integer> {
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
            if *exponent < 0 {
                r.invert_mut(&self.modulus).ok()?
            }
            Some(r)
        } else {
            self.table[0]
                .pow_mod_ref(exponent, &self.modulus)
                .map(Integer::from)
        }
    }
}
