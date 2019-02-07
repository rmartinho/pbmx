use pbmx_chain::Id;
use pbmx_curve::{
    map,
    vtmf::{Mask, Stack, Vtmf},
};
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    str::{self, FromStr},
};

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

    pub fn insert(&mut self, stack: Stack) {
        self.map.insert(stack.id(), stack);
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

struct DisplayStackContents<'a>(&'a [Mask], &'a Vtmf);
pub fn display_stack_contents<'a>(stack: &'a [Mask], vtmf: &'a Vtmf) -> impl Display + 'a {
    DisplayStackContents(stack, vtmf)
}

impl<'a> Display for DisplayStackContents<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut first = true;
        let mut last_in_seq = None;
        let mut unfinished_seq = false;
        let mut count_encrypted = 0;
        write!(f, "[")?;
        for m in self.0.iter() {
            let u = self.1.unmask_open(m);
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
