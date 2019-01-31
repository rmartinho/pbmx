use pbmx_chain::Id;
use pbmx_curve::{keys::Fingerprint, vtmf::SecretShare};
use std::collections::HashMap;

#[derive(Clone, Default, Debug)]
pub struct SecretMap {
    shares: HashMap<Id, Vec<SecretShare>>,
    owners: HashMap<Id, Vec<Fingerprint>>,
}

impl SecretMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.shares.keys()
    }

    pub fn shares(&self, id: Id) -> &[SecretShare] {
        &self.shares[&id]
    }

    pub fn fingerprints(&self, id: Id) -> &[Fingerprint] {
        &self.owners[&id]
    }
}
