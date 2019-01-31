use pbmx_chain::Id;
use pbmx_curve::{keys::Fingerprint, vtmf::Mask};
use std::collections::HashMap;

#[derive(Clone, Default, Debug)]
pub struct RandomMap {
    entropy: HashMap<Id, Mask>,
    owners: HashMap<Id, Vec<Fingerprint>>,
}

impl RandomMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entropy.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, id: Id, owner: Fingerprint, entropy: Mask) {
        self.entropy
            .entry(id)
            .and_modify(|e| {
                e.0 += entropy.0;
                e.1 += entropy.1;
            })
            .or_insert(entropy);

        self.owners
            .entry(id)
            .and_modify(|v| v.push(owner))
            .or_insert_with(|| vec![owner]);
    }

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.entropy.keys()
    }

    pub fn entropy(&self, id: Id) -> &Mask {
        &self.entropy[&id]
    }

    pub fn fingerprints(&self, id: Id) -> &[Fingerprint] {
        &self.owners[&id]
    }
}
