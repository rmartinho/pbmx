use super::{cp, Mask, Proof, Vtmf};
use crate::crypto::key::Fingerprint;
use rug::Integer;
use std::collections::HashSet;

// TODO serialization
/// The VTMF decryption protocol
pub struct Decryption<'a> {
    vtmf: &'a Vtmf,
    c: (Integer, Integer),
    d: Integer,
    seen: HashSet<Fingerprint>,
}

impl<'a> Decryption<'a> {
    pub(super) fn new(vtmf: &'a Vtmf, c: Mask) -> Self {
        Self {
            d: self_secret(&c.0, &vtmf.sk.x, vtmf.g.modulus()),
            seen: HashSet::new(),
            vtmf,
            c,
        }
    }

    /// Publishing step of the verifiable decryption protocol
    pub fn reveal_share(&mut self) -> Result<(Integer, Proof), DecryptionError> {
        if self.seen.len() > 0 {
            return Err(DecryptionError::RepeatedReveal);
        }

        let g = self.vtmf.g.generator();

        let hi = self.vtmf.g.element(&self.vtmf.sk.x);
        let di = self_secret(&self.c.0, &self.vtmf.sk.x, self.vtmf.g.modulus());
        let proof = cp::prove(self.vtmf, &di, &hi, &self.c.0, g, &self.vtmf.sk.x);
        self.seen.insert(self.vtmf.fp.clone());
        Ok((di, proof))
    }

    /// Accumulate step of the verifiable decryption protocol
    pub fn accumulate_share(
        &mut self,
        pk_fp: &Fingerprint,
        di: &Integer,
        proof: &Proof,
    ) -> Result<(), DecryptionError> {
        if self.seen.len() == 0 || self.is_complete() {
            return Err(DecryptionError::TooManyShares);
        }

        let g = self.vtmf.g.generator();
        let pk = self
            .vtmf
            .pki
            .get(pk_fp)
            .ok_or(DecryptionError::UnknownKeyShare)?;

        if cp::verify(self.vtmf, di, &pk.h, &self.c.0, g, proof) {
            self.d *= di;
            self.seen.insert(pk.fingerprint());
            Ok(())
        } else {
            Err(DecryptionError::ProofFailure)
        }
    }

    /// Tests whether
    pub fn is_complete(&self) -> bool {
        self.seen.len() == self.vtmf.n as usize
    }

    /// Decrypting step of the verifiable decryption protocol
    pub fn decrypt(self, c: &(Integer, Integer)) -> Result<Integer, DecryptionError> {
        if !self.is_complete() {
            return Err(DecryptionError::IncompleteSecret);
        }

        let p = self.vtmf.g.modulus();
        let d1 = Integer::from(self.d.invert_ref(&p).unwrap());

        Ok(&c.1 * d1)
    }
}

fn self_secret(c1: &Integer, x: &Integer, p: &Integer) -> Integer {
    Integer::from(c1.pow_mod_ref(x, p).unwrap())
}

/// An error resulting from wrong usage of the decryption protocol
#[derive(Copy, Clone, Debug)]
pub enum DecryptionError {
    /// Occurs when the reveal step is attempted a second time
    RepeatedReveal,
    /// Occurs when there are more key shares than expected
    TooManyShares,
    /// Occurs when an unknown public key share is used
    UnknownKeyShare,
    /// Occurs when a proof of a share is incorrect
    ProofFailure,
    /// Occurs when decryption is attempted without all shares of the secret
    IncompleteSecret,
}
