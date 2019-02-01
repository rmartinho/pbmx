use pbmx_chain::Id;
use pbmx_curve::vtmf::Mask;
use std::{
    collections::HashMap,
    str::{self, FromStr},
};

pub type Stack = Vec<Mask>;

#[derive(Clone, Default, Debug)]
pub struct StackMap {
    map: HashMap<Id, Stack>,
    name_map: HashMap<String, Id>,
}

impl StackMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, stack: Vec<Mask>) {
        self.map.insert(Id::of(&stack).unwrap(), stack);
    }

    pub fn set_name(&mut self, id: Id, name: String) {
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

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.map.keys()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.name_map.keys().map(String::as_str)
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
