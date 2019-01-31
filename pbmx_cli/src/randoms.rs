use pbmx_chain::Id;
use pbmx_curve::{keys::Fingerprint, vtmf::Mask};
use std::collections::HashMap;

#[derive(Clone, Default, Debug)]
pub struct RandomMap(HashMap<Id, (u64, Mask, Vec<Fingerprint>)>);

impl RandomMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, id: Id, n: u64) {
        self.0.insert(id, (n, Mask::default(), Vec::new()));
    }

    pub fn add_entropy(&mut self, id: Id, owner: Fingerprint, entropy: Mask) {
        let (_, m, fp) = self.0.get_mut(&id).unwrap();
        m.0 += entropy.0;
        m.1 += entropy.1;
        fp.push(owner);
    }

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.0.keys()
    }

    pub fn entropy(&self, id: Id) -> &Mask {
        &self.0[&id].1
    }

    pub fn fingerprints(&self, id: Id) -> &[Fingerprint] {
        &self.0[&id].2
    }
}
