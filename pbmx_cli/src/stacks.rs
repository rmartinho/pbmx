use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use pbmx_chain::Id;
use pbmx_curve::{
    keys::Fingerprint,
    map,
    vtmf::{SecretShare, Stack, Vtmf},
};
use qp_trie::Trie;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter, str,
};

#[derive(Clone, Default, Debug)]
pub struct StackEntry {
    pub stack: Stack,
    pub secret: Vec<SecretShare>,
    pub fingerprints: Vec<Fingerprint>,
}

impl From<Stack> for StackEntry {
    fn from(stack: Stack) -> Self {
        Self {
            secret: iter::repeat(RistrettoPoint::identity())
                .take(stack.len())
                .collect(),
            stack,
            fingerprints: Vec::new(),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct StackMap {
    len: usize,
    map: Trie<Id, StackEntry>,
    name_map: HashMap<String, Id>,
}

impl StackMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, stack: Stack) {
        let old = self.map.insert(stack.id(), StackEntry::from(stack));
        if old.is_none() {
            self.len += 1;
        }
    }

    pub fn set_name(&mut self, id: Id, name: String) {
        self.name_map
            .entry(name)
            .and_modify(|e| *e = id)
            .or_insert(id);
    }

    pub fn add_secret_share(&mut self, id: Id, owner: Fingerprint, shares: Vec<SecretShare>) {
        let entry = &mut self.map[&id];
        for (s0, s1) in entry.secret.iter_mut().zip(shares.iter()) {
            *s0 += s1;
        }
        entry.fingerprints.push(owner);
    }

    pub fn get_by_str(&self, s: &str) -> Option<&StackEntry> {
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

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.map.keys()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.name_map.keys().map(String::as_str)
    }

    pub fn is_name(&self, s: &str) -> bool {
        self.name_map.contains_key(s)
    }

    pub fn get_by_id(&self, id: &Id) -> Option<&StackEntry> {
        self.map.get(id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&StackEntry> {
        self.get_by_id(self.name_map.get(name)?)
    }
}

struct DisplayStackContents<'a>(&'a StackEntry, &'a Vtmf);
pub fn display_stack_contents<'a>(stack: &'a StackEntry, vtmf: &'a Vtmf) -> impl Display + 'a {
    DisplayStackContents(stack, vtmf)
}

impl<'a> Display for DisplayStackContents<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let my_fp = &self.1.private_key().fingerprint();
        let mut first = true;
        let mut last_in_seq = None;
        let mut unfinished_seq = false;
        let mut count_encrypted = 0;
        write!(f, "[")?;
        for (m, s) in self.0.stack.iter().zip(self.0.secret.iter()) {
            let mut m = self.1.unmask(m, s);
            if !self.0.fingerprints.contains(my_fp) {
                m = self.1.unmask_private(&m);
            }
            let u = self.1.unmask_open(&m);
            if let Some(token) = map::from_curve(&u) {
                if count_encrypted > 0 {
                    if !first {
                        write!(f, " ")?;
                    }
                    write!(f, "?{}", count_encrypted)?;
                    first = false;
                    count_encrypted = 0;
                }
                if let Some(last) = last_in_seq {
                    if last + 1 == token {
                        unfinished_seq = true;
                    } else {
                        if unfinished_seq {
                            write!(f, "-{}", last)?;
                            unfinished_seq = false;
                        }
                        write!(f, " {}", token)?;
                    }
                } else {
                    if !first {
                        write!(f, " ")?;
                    }
                    write!(f, "{}", token)?;
                }
                last_in_seq = Some(token);
                first = false;
            } else {
                last_in_seq = None;
                count_encrypted += 1;
            }
        }
        if count_encrypted > 0 {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "?{}", count_encrypted)?;
        }
        if unfinished_seq {
            let last = last_in_seq.unwrap();
            write!(f, "-{}", last)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}
