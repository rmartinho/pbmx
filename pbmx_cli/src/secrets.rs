use pbmx_chain::Id;
use pbmx_curve::{keys::Fingerprint, vtmf::SecretShare};
use std::collections::HashMap;

#[derive(Clone, Default, Debug)]
pub struct SecretMap(HashMap<Id, (Vec<SecretShare>, Vec<Fingerprint>)>);

impl SecretMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, id: Id, owner: Fingerprint, shares: Vec<SecretShare>) {
        self.0
            .entry(id)
            .and_modify(|(s, fp)| {
                for (s0, s1) in s.iter_mut().zip(shares.iter()) {
                    *s0 += s1;
                }
                fp.push(owner);
            })
            .or_insert_with(|| (shares, vec![owner]));
    }

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.0.keys()
    }

    pub fn shares(&self, id: Id) -> &[SecretShare] {
        &self.0[&id].0
    }

    pub fn fingerprints(&self, id: Id) -> &[Fingerprint] {
        &self
            .0
            .get(&id)
            .map(|x| x.1.as_slice())
            .unwrap_or(&NO_FINGERPRINTS)
    }
}

const NO_FINGERPRINTS: [Fingerprint; 0] = [];
