use pbmx_chain::Id;
use pbmx_curve::vtmf::Mask;
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    ops::Deref,
    str::{self, FromStr},
};

#[derive(Clone, Debug, Eq)]
pub struct Stack(Vec<Mask>);

impl Deref for Stack {
    type Target = [Mask];

    fn deref(&self) -> &[Mask] {
        &self.0
    }
}

#[derive(Clone, Default, Debug)]
pub struct StackMap {
    map: HashMap<Id, Stack>,
    name_map: HashMap<String, Id>,
}

impl Stack {
    pub fn id(&self) -> Id {
        Id::of(&self.0).unwrap()
    }
}

impl StackMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn insert(&mut self, stack: Stack) {
        self.map.insert(stack.id(), stack);
    }

    pub fn set_name(&mut self, name: String, id: Id) {
        self.name_map
            .entry(name)
            .and_modify(|e| *e = id)
            .or_insert(id);
    }

    pub fn get_by_str(&self, s: &str) -> Option<&Stack> {
        if let Ok(id) = Id::from_str(s) {
            if let Some(s) = self.get_by_id(&id) {
                return Some(s);
            }
        }
        self.get_by_name(s)
    }

    pub fn get_by_id(&self, id: &Id) -> Option<&Stack> {
        self.map.get(id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Stack> {
        self.get_by_id(self.name_map.get(name)?)
    }

    pub fn named_stacks(&self) -> impl Iterator<Item = (&str, &Stack)> {
        self.name_map
            .keys()
            .map(move |k| (k.as_str(), self.get_by_name(k).unwrap()))
    }
}

impl<T> From<T> for Stack
where
    T: Into<Vec<Mask>>,
{
    fn from(t: T) -> Self {
        Self(t.into())
    }
}

impl PartialEq for Stack {
    fn eq(&self, rhs: &Self) -> bool {
        self.id() == rhs.id()
    }
}

impl Hash for Stack {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.id().hash(h);
    }
}
