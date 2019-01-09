use crate::{
    group::Group,
    keys::{Keys, PrivateKey, PublicKey},
    vtmf::Vtmf,
    Result,
};
use rand::{thread_rng, Rng};

/// The VTMF key exchange protocol
pub struct KeyExchange {
    g: Group,
    n: u32,
    sk: Option<PrivateKey>,
    pk: Option<PublicKey>,
    pki: Vec<PublicKey>,
}

impl KeyExchange {
    /// Creates a new [KeyExchange] instance for a given number of parties with
    /// an agreed group.
    pub fn new(g: Group, parties: u32) -> Self {
        assert!(parties > 1);
        Self {
            g,
            n: parties,
            sk: None,
            pk: None,
            pki: Vec::new(),
        }
    }

    /// Gets the number of parties in this [KeyExchange].
    pub fn parties(&self) -> u32 {
        self.n
    }

    /// Gets the group for this [KeyExchange].
    pub fn group(&self) -> &Group {
        &self.g
    }

    /// Tests whether the private key for this VTMF has been generated.
    pub fn has_private_key(&self) -> bool {
        !self.pki.is_empty()
    }

    /// Tests whether the keys for this VTMF have been exchanged.
    pub fn has_all_keys(&self) -> bool {
        self.pki.len() == self.n as usize
    }

    /// Uses a given private key for this VTMF and returns the corresponding
    /// public key to be shared.
    pub fn use_private_key(&mut self, sk: PrivateKey) -> Result<PublicKey> {
        if self.has_private_key() {
            return Err(KeyExchangeError::RepeatedKeyGeneration.into());
        }
        if self.g != *sk.group() {
            return Err(KeyExchangeError::InvalidPrivateKey.into());
        }

        let pk = sk.public_key();
        self.sk = Some(sk);
        self.pk = Some(pk.clone());
        self.pki.push(pk.clone());
        Ok(pk)
    }

    /// Generates a private key for this VTMF and returns the corresponding
    /// public key to be shared.
    pub fn generate_key(&mut self) -> Result<PublicKey> {
        if self.has_private_key() {
            return Err(KeyExchangeError::RepeatedKeyGeneration.into());
        }

        let (sk, pk) = thread_rng().sample(&Keys(&self.g));
        self.sk = Some(sk);
        self.pk = Some(pk.clone());
        self.pki.push(pk.clone());
        Ok(pk)
    }

    /// Updates the public key with another party's contribution
    pub fn update_key(&mut self, pk: PublicKey) -> Result<()> {
        if !self.has_private_key() {
            return Err(KeyExchangeError::NoKeyGenerated.into());
        }
        if self.has_all_keys() {
            return Err(KeyExchangeError::RepeatedKeyGeneration.into());
        }
        if self.g != *pk.group() {
            return Err(KeyExchangeError::InvalidPublicKey.into());
        }

        self.pk.as_mut().unwrap().combine(&pk);
        self.pki.push(pk);
        Ok(())
    }

    /// Finalizes the key exchange protocol and creates a [Vtmf] instance
    pub fn finalize(self) -> Result<Vtmf> {
        if !self.has_all_keys() {
            return Err(KeyExchangeError::IncompleteExchange.into());
        }

        // SAFE: KeyExchange holds the same invariant as Vtmf
        unsafe {
            Ok(Vtmf::new_unchecked(
                self.g,
                self.n,
                self.sk.unwrap(),
                self.pk.unwrap(),
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
    /// Occurs when a key exchange is attempted with a key from the wrong group
    InvalidPrivateKey,
    /// Occurs when attempting to finalize the exchange before it is complete
    IncompleteExchange,
}

#[cfg(test)]
mod test {}
