use crate::{
    crypto::{
        key::{Keys, PrivateKey, PublicKey},
        vtmf::Vtmf,
    },
    num::schnorr::SchnorrGroup,
};
use rand::{thread_rng, Rng};

/// The VTMF key exchange protocol
#[derive(Serialize, Deserialize)]
pub struct KeyExchange {
    g: SchnorrGroup,
    n: u32,
    sk: Option<PrivateKey>,
    pk: Option<PublicKey>,
    kex: u32,
}

impl KeyExchange {
    /// Creates a new [KeyExchange] instance for a given number of parties with
    /// an agreed group.
    pub fn new(g: SchnorrGroup, parties: u32) -> Self {
        assert!(parties > 1);
        Self {
            g,
            n: parties,
            sk: None,
            pk: None,
            kex: 0,
        }
    }

    /// Tests whether the private key for this VTMF has been generated.
    pub fn has_private_key(&self) -> bool {
        self.kex > 0
    }

    /// Tests whether the keys for this VTMF have been exchanged.
    pub fn has_all_keys(&self) -> bool {
        self.kex == self.n
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
        self.kex = 1;
        Ok(pk)
    }

    /// Updates the public key with another party's contribution
    pub fn update_key(&mut self, pk: &PublicKey) -> Result<(), KeyExchangeError> {
        if !self.has_private_key() {
            return Err(KeyExchangeError::NoKeyGenerated);
        }
        if self.has_all_keys() {
            return Err(KeyExchangeError::RepeatedKeyGeneration);
        }
        if self.g != pk.g {
            return Err(KeyExchangeError::InvalidPublicKey);
        }

        self.pk.as_mut().unwrap().h *= &pk.h;
        self.kex += 1;
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
            ))
        }
    }
}

/// An error resulting from wrong usage of the key exchange protocol
#[derive(Copy, Clone, Debug)]
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
