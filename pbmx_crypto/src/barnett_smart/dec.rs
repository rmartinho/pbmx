use super::{dlog_eq, DlogEqProof, Mask, Vtmf};
use crate::elgamal::Fingerprint;
use rug::Integer;
use std::collections::HashSet;

/// One party's share of a secret
pub type SecretShare = Integer;

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
            d: Integer::new(),
            seen: HashSet::new(),
            vtmf,
            c,
        }
    }

    /// Publishing step of the verifiable decryption protocol
    pub fn reveal_share(&mut self) -> Result<(SecretShare, DlogEqProof), DecryptionError> {
        if self.seen.len() > 0 {
            return Err(DecryptionError::RepeatedReveal);
        }

        let g = self.vtmf.g.generator();
        let p = self.vtmf.g.modulus();

        let hi = self.vtmf.g.element(&self.vtmf.sk.x);
        self.d = Integer::from(self.c.0.pow_mod_ref(&self.vtmf.sk.x, p).unwrap());
        let proof = dlog_eq::prove(
            self.vtmf,
            &self.d,
            &hi,
            &self.c.0,
            g,
            &self.vtmf.sk.x,
            None,
            Some(&self.vtmf.g.fpowm),
        );
        self.seen.insert(self.vtmf.fp.clone());
        Ok((self.d.clone(), proof))
    }

    /// Accumulate step of the verifiable decryption protocol
    pub fn add_share(
        &mut self,
        pk_fp: &Fingerprint,
        di: &SecretShare,
        proof: &DlogEqProof,
    ) -> Result<(), DecryptionError> {
        if self.seen.len() == 0 || self.is_complete() {
            return Err(DecryptionError::TooManyShares);
        }

        let g = self.vtmf.g.generator();
        let p = self.vtmf.g.modulus();
        let pk = self
            .vtmf
            .pki
            .get(pk_fp)
            .ok_or(DecryptionError::UnknownKeyShare)?;

        if dlog_eq::verify(
            self.vtmf,
            di,
            &pk.h,
            &self.c.0,
            g,
            proof,
            None,
            Some(&self.vtmf.g.fpowm),
        ) {
            self.d *= di;
            self.d %= p;
            self.seen.insert(pk.fingerprint());
            Ok(())
        } else {
            Err(DecryptionError::ProofFailure)
        }
    }

    /// Tests whether all shares have been provided
    pub fn is_complete(&self) -> bool {
        self.seen.len() == self.vtmf.n as usize
    }

    /// Decrypting step of the verifiable decryption protocol
    pub fn decrypt(self) -> Result<Integer, DecryptionError> {
        if !self.is_complete() {
            return Err(DecryptionError::IncompleteSecret);
        }

        let p = self.vtmf.g.modulus();
        let d1 = Integer::from(self.d.invert_ref(&p).unwrap());

        Ok(&self.c.1 * d1 % p)
    }
}

/// An error resulting from wrong usage of the decryption protocol
#[derive(Debug)]
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
