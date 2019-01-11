use pbmx_blocks::block::Id;
use pbmx_crypto::vtmf::Mask;
use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    str::{self, FromStr},
};

#[derive(Clone, Debug, Eq)]
pub struct Stack {
    id: Id,
    tokens: Vec<Mask>,
}

#[derive(Clone, Default, Debug)]
pub struct StackMap {
    vec: Vec<Stack>,
    id_map: HashMap<Id, usize>,
    name_map: HashMap<String, usize>,
}

impl Stack {
    pub fn tokens(&self) -> &[Mask] {
        &self.tokens
    }

    pub fn id(&self) -> Id {
        self.id
    }
}

impl StackMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn insert(&mut self, stack: Stack) {
        let idx = self.vec.len();
        let id = stack.id();
        self.vec.push(stack);
        self.id_map.insert(id, idx);
    }

    pub fn set_name_index(&mut self, index: usize, name: String) {
        self.name_map
            .entry(name)
            .and_modify(|e| *e = index)
            .or_insert(index);
    }

    pub fn set_name_id(&mut self, id: &Id, name: String) {
        self.set_name_index(*self.id_map.get(id).unwrap(), name);
    }

    pub fn get_by_str(&self, s: &str) -> Option<&Stack> {
        if let Ok(idx) = str::parse::<usize>(s) {
            if let Some(s) = self.get_by_index(idx - 1) {
                return Some(s);
            }
        }

        if let Ok(id) = Id::from_str(s) {
            if let Some(s) = self.get_by_id(&id) {
                return Some(s);
            }
        }
        self.get_by_name(s)
    }

    pub fn get_by_index(&self, index: usize) -> Option<&Stack> {
        if index < self.len() {
            Some(&self.vec[index])
        } else {
            None
        }
    }

    pub fn get_by_id(&self, id: &Id) -> Option<&Stack> {
        self.get_by_index(*self.id_map.get(id)?)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Stack> {
        self.get_by_index(*self.name_map.get(name)?)
    }

    pub fn named_stacks(&self) -> impl Iterator<Item = (&str, &Stack)> {
        self.name_map
            .keys()
            .map(move |k| (k.as_str(), self.get_by_name(k).unwrap()))
    }
}

impl Borrow<Id> for Stack {
    fn borrow(&self) -> &Id {
        &self.id
    }
}

impl<T> From<T> for Stack
where
    T: Into<Vec<Mask>>,
{
    fn from(t: T) -> Self {
        let tokens = t.into();
        Self {
            id: Id::of(&tokens).unwrap(),
            tokens,
        }
    }
}

impl PartialEq for Stack {
    fn eq(&self, rhs: &Self) -> bool {
        self.id == rhs.id
    }
}

impl Hash for Stack {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.id.hash(h);
    }
}

impl Display for Stack {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut last_encrypted = 0;
        write!(f, "[")?;
        let mut comma = false;
        for (c1, c2) in self.tokens.iter() {
            if *c1 == 1 {
                if last_encrypted > 0 {
                    write!(f, "{}", last_encrypted)?;
                    last_encrypted = 0;
                }
                if comma {
                    write!(f, ",")?;
                } else {
                    comma = true;
                }
                write!(f, "{}", c2)?;
            } else {
                if last_encrypted == 0 {
                    if comma {
                        write!(f, ",")?;
                    } else {
                        comma = true;
                    }
                    write!(f, "?")?;
                }
                last_encrypted += 1;
            }
        }
        if last_encrypted > 0 {
            write!(f, "{}", last_encrypted)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}
