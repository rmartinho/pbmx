use crate::{
    chain::Id,
    crypto::{
        keys::Fingerprint,
        vtmf::{Mask, SecretShare, Stack},
    },
};
use qp_trie::Trie;
use std::{collections::HashMap, str};

/// A map of published secrets
pub type SecretMap = HashMap<Mask, (SecretShare, Vec<Fingerprint>)>;

/// A map of private secrets
pub type PrivateSecretMap = HashMap<Mask, Mask>;

/// A map of stacks
#[derive(Clone, Default, Debug)]
pub struct StackMap {
    len: usize,
    map: Trie<Id, Stack>,
    name_map: HashMap<String, Id>,
    secrets: SecretMap,
    private_secrets: PrivateSecretMap,
}

impl StackMap {
    /// Creates a new empty map
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets the number of stacks in the map
    pub fn len(&self) -> usize {
        self.len
    }

    /// Tests whether the map is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts a new stack in the map
    pub fn insert(&mut self, stack: Stack) {
        if !self.map.contains_key(&stack.id()) {
            self.map.insert(stack.id(), stack);
            self.len += 1;
        }
    }

    /// Tests whether the map contains a stack with the given ID
    pub fn contains(&mut self, id: &Id) -> bool {
        self.map.contains_key(id)
    }

    /// Associates a stack with a name
    pub fn set_name(&mut self, id: Id, name: String) {
        self.name_map
            .entry(name)
            .and_modify(|e| *e = id)
            .or_insert(id);
    }

    /// Adds a share of a stack's secret
    pub fn add_secret_share(&mut self, id: Id, owner: Fingerprint, shares: Vec<SecretShare>) {
        let stack = &mut self.map[&id];
        for (m, di) in stack.iter().zip(shares.iter()) {
            self.secrets
                .entry(*m)
                .and_modify(|(d, fp)| {
                    if !fp.contains(&owner) {
                        *d += di;
                        fp.push(owner);
                    }
                })
                .or_insert_with(|| (*di, vec![owner]));
        }
    }

    /// Stores a private secret
    pub fn add_private_secrets<It>(&mut self, it: It) -> Result<(), ()>
    where
        It: Iterator<Item = (Mask, Mask)>,
    {
        self.private_secrets.extend(it);
        Ok(())
    }

    /// Finds a stack by its ID or name
    pub fn get_by_str(&self, s: &str) -> Option<&Stack> {
        let hex_to_byte =
            |c| u8::from_str_radix(str::from_utf8(c).map_err(|_| ())?, 16).map_err(|_| ());

        self.get_by_name(s).or_else(|| {
            let bytes: Vec<_> = s
                .as_bytes()
                .chunks(2)
                .map(hex_to_byte)
                .collect::<Result<_, _>>()
                .ok()?;
            let mut prefixed = self.map.iter_prefix(bytes.as_slice());
            prefixed.next().xor(prefixed.next()).map(|(_, v)| v)
        })
    }

    /// Gets all stack IDs in the map
    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.map.keys()
    }

    /// Gets all stack names in the map
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.name_map.keys().map(String::as_str)
    }

    /// Gets all published secrets in the map
    pub fn secrets(&self) -> &SecretMap {
        &self.secrets
    }

    /// Gets all private secrets in the map
    pub fn private_secrets(&self) -> &PrivateSecretMap {
        &self.private_secrets
    }

    /// Tests whether a string is a stack name
    pub fn is_name(&self, s: &str) -> bool {
        self.name_map.contains_key(s)
    }

    /// Finds a stack by its ID
    pub fn get_by_id(&self, id: &Id) -> Option<&Stack> {
        self.map.get(id)
    }

    /// Finds a stack by its name
    pub fn get_by_name(&self, name: &str) -> Option<&Stack> {
        self.get_by_id(self.name_map.get(name)?)
    }
}
