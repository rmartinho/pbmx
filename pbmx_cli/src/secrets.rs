use pbmx_chain::Id;
use pbmx_curve::{keys::Fingerprint, vtmf::SecretShare};
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct SecretMap {
    shares: HashMap<Id, Vec<SecretShare>>,
    owners: HashMap<Id, Vec<Fingerprint>>,
}

impl SecretMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: Id, owner: Fingerprint, shares: Vec<SecretShare>) {
        self.shares
            .entry(id)
            .and_modify(|v| {
                for (s, s1) in v.iter_mut().zip(shares.iter()) {
                    *s += s1;
                }
            })
            .or_insert(shares);

        self.owners
            .entry(id)
            .and_modify(|v| v.push(owner))
            .or_insert_with(|| vec![owner]);
    }

    pub fn get_shares(&self, id: Id) -> &[SecretShare] {
        &self.shares[&id]
    }

    pub fn get_fingerprints(&self, id: Id) -> &[Fingerprint] {
        &self.owners[&id]
    }
}
