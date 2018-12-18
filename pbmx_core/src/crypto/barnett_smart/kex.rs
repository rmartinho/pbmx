use crate::crypto::{
    barnett_smart::Vtmf,
    elgamal::{Fingerprint, Keys, PrivateKey, PublicKey},
    schnorr,
};
use rand::{thread_rng, Rng};

/// The VTMF key exchange protocol
pub struct KeyExchange {
    g: schnorr::Group,
    n: u32,
    sk: Option<PrivateKey>,
    pk: Option<PublicKey>,
    fp: Option<Fingerprint>,
    pki: Vec<PublicKey>,
}

impl KeyExchange {
    /// Creates a new [KeyExchange] instance for a given number of parties with
    /// an agreed group.
    pub fn new(g: schnorr::Group, parties: u32) -> Self {
        assert!(parties > 1);
        Self {
            g,
            n: parties,
            sk: None,
            pk: None,
            fp: None,
            pki: Vec::new(),
        }
    }

    /// Tests whether the private key for this VTMF has been generated.
    pub fn has_private_key(&self) -> bool {
        self.pki.len() > 0
    }

    /// Tests whether the keys for this VTMF have been exchanged.
    pub fn has_all_keys(&self) -> bool {
        self.pki.len() == self.n as usize
    }

    /// Generates a private key for this VTMF and returns the corresponding
    /// public key to be shared.
    pub fn generate_key(&mut self) -> Result<PublicKey, KeyExchangeError> {
        if self.has_private_key() {
            return Err(KeyExchangeError::RepeatedKeyGeneration);
        }

        let (sk, pk) = thread_rng().sample(&Keys(&self.g));
        self.sk = Some(sk);
        self.pk = Some(pk.clone());
        self.fp = Some(pk.fingerprint());
        self.pki.push(pk.clone());
        Ok(pk)
    }

    /// Updates the public key with another party's contribution
    pub fn update_key(&mut self, pk: PublicKey) -> Result<(), KeyExchangeError> {
        if !self.has_private_key() {
            return Err(KeyExchangeError::NoKeyGenerated);
        }
        if self.has_all_keys() {
            return Err(KeyExchangeError::RepeatedKeyGeneration);
        }
        if self.g != pk.g {
            return Err(KeyExchangeError::InvalidPublicKey);
        }

        let h = &mut self.pk.as_mut().unwrap().h;
        *h *= &pk.h;
        *h %= self.g.modulus();
        self.pki.push(pk);
        Ok(())
    }

    /// Finalizes the key exchange protocol and creates a [Vtmf] instance
    pub fn finalize(self) -> Result<Vtmf, KeyExchangeError> {
        if !self.has_all_keys() {
            return Err(KeyExchangeError::IncompleteExchange);
        }

        // SAFE: KeyExchange holds the same invariant as Vtmf
        unsafe {
            Ok(Vtmf::new_unchecked(
                self.g,
                self.n,
                self.sk.unwrap(),
                self.pk.unwrap(),
                self.fp.unwrap(),
                self.pki,
            ))
        }
    }
}

/// An error resulting from wrong usage of the key exchange protocol
#[derive(Debug)]
pub enum KeyExchangeError {
    /// Occurs when an operation that requires a key is attempted before
    /// generating keys
    NoKeyGenerated,
    /// Occurs when key generation is attempted after a key has already been
    /// generated
    RepeatedKeyGeneration,
    /// Occurs when a key exchange is attempted with a key from the wrong group
    InvalidPublicKey,
    /// Occurs when attempting to finalize the exchange before it is complete
    IncompleteExchange,
}

#[cfg(test)]
mod test {}
