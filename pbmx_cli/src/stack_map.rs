use crate::Config;
use pbmx_kit::{
    chain::Id,
    crypto::{
        keys::Fingerprint,
        map,
        vtmf::{Mask, SecretShare, Stack, Vtmf},
    },
};
use qp_trie::Trie;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    str,
};

pub type SecretMap = HashMap<Mask, (SecretShare, Vec<Fingerprint>)>;
pub type PrivateSecretMap = HashMap<Mask, Mask>;

#[derive(Clone, Default, Debug)]
pub struct StackMap {
    len: usize,
    map: Trie<Id, Stack>,
    name_map: HashMap<String, Id>,
    pub secrets: SecretMap,
    pub private_secrets: PrivateSecretMap,
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
        if !self.map.contains_key(&stack.id()) {
            self.map.insert(stack.id(), stack);
            self.len += 1;
        }
    }

    pub fn contains(&mut self, id: &Id) -> bool {
        self.map.contains_key(id)
    }

    pub fn set_name(&mut self, id: Id, name: String) {
        self.name_map
            .entry(name)
            .and_modify(|e| *e = id)
            .or_insert(id);
    }

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

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.map.keys()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.name_map.keys().map(String::as_str)
    }

    pub fn is_name(&self, s: &str) -> bool {
        self.name_map.contains_key(s)
    }

    pub fn get_by_id(&self, id: &Id) -> Option<&Stack> {
        self.map.get(id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Stack> {
        self.get_by_id(self.name_map.get(name)?)
    }
}

struct DisplayStackContents<'a>(
    &'a Stack,
    &'a SecretMap,
    &'a PrivateSecretMap,
    &'a Vtmf,
    &'a Config,
);
pub fn display_stack_contents<'a>(
    stack: &'a Stack,
    secrets: &'a SecretMap,
    private_secrets: &'a PrivateSecretMap,
    vtmf: &'a Vtmf,
    config: &'a Config,
) -> impl Display + 'a {
    DisplayStackContents(stack, secrets, private_secrets, vtmf, config)
}

impl<'a> Display for DisplayStackContents<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut first = true;
        let mut last_in_seq = None;
        let mut unfinished_seq = false;
        let mut count_encrypted = 0;
        write!(f, "[")?;
        let my_fp = &self.3.private_key().fingerprint();
        for m in self.0.iter() {
            let mut m = *m;
            while let Some(d) = self.2.get(&m) {
                m -= d;
            }
            if let Some((d, fp)) = self.1.get(&m) {
                m = self.3.unmask(&m, d);
                if !fp.contains(my_fp) {
                    m = self.3.unmask_private(&m);
                }
            }
            let u = self.3.unmask_open(&m);
            if let Some(token) = map::from_curve(&u) {
                if count_encrypted > 0 {
                    if !first {
                        write!(f, " ")?;
                    }
                    write!(f, "?{}", count_encrypted)?;
                    first = false;
                    count_encrypted = 0;
                }
                if self.4.tokens.is_empty() {
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
                } else {
                    if !first {
                        write!(f, " ")?;
                    }
                    let s = self.4.tokens.get(&token);
                    if let Some(s) = s {
                        write!(f, "{}", s)?;
                    } else {
                        write!(f, "{}", token)?;
                    }
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
