use super::Vtmf;
use rug::Integer;

/// One instance of the verifiable decryption protocol
pub struct Decryption<'a> {
    vtmf: &'a Vtmf,
    c: (Integer, Integer),
    d: Integer,
}

impl<'a> Decryption<'a> {
    pub(super) fn new(vtmf: &'a Vtmf, c: (Integer, Integer)) -> Self {
        Self {
            d: Decryption::self_secret(&c.0, &vtmf.sk.x, vtmf.g.modulus()),
            vtmf,
            c,
        }
    }

    fn self_secret(c1: &Integer, x: &Integer, p: &Integer) -> Integer {
        Integer::from(c1.pow_mod_ref(x, p).unwrap())
    }

    /// Publishing step of the verifiable decryption protocol
    pub fn reveal_mask(&self) -> Integer {
        Decryption::self_secret(&self.c.0, &self.vtmf.sk.x, self.vtmf.g.modulus())
    }

    /// Accumulate step of the verifiable decryption protocol
    pub fn accumulate_mask(&mut self, di: &Integer) {
        self.d *= di;
    }

    /// Decrypting step of the verifiable decryption protocol
    pub fn decrypt(self, c: &(Integer, Integer)) -> Integer {
        let p = self.vtmf.g.modulus();
        let d1 = Integer::from(self.d.invert_ref(&p).unwrap());

        &c.1 * d1
    }
}
