use crate::{
    error::{Error, Result},
    stacks::{Stack, StackMap},
};
use pbmx_blocks::{block::Id, chain::Chain};
use pbmx_crypto::{
    group::Group,
    keys::{PrivateKey, PublicKey},
    vtmf::Vtmf,
};
use std::collections::HashMap;

pub struct ParsedChain {
    name: String,
    group: Option<Group>,
    vtmf: Option<Vtmf>,
    stacks: StackMap,
}

impl ParsedChain {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn group(&self) -> Option<&Group> {
        self.vtmf().map(Vtmf::group).or(self.group.as_ref())
    }

    pub fn parties(&self) -> u32 {
        self.vtmf().map(Vtmf::parties).unwrap_or_default()
    }

    pub fn vtmf(&self) -> Option<&Vtmf> {
        self.vtmf.as_ref()
    }

    pub fn stacks(&self) -> &StackMap {
        &self.stacks
    }

    pub fn print_out(&self) {
        println!("# Game: {} {}p", self.name(), self.parties());
        for (n, s) in self.stacks().named_stacks() {
            println!("# Stack {} [{:16}]:\n\t{}", n, s.id(), s);
        }
    }
}

#[derive(Default)]
struct ParseState {
    name: String,
    group: Option<Group>,
    private_key: Option<PrivateKey>,
    vtmf: Option<Vtmf>,
    stacks: Vec<Stack>,
    stack_names: HashMap<String, Id>,
}

pub fn parse_chain(chain: &Chain, private_key: &Option<PrivateKey>) -> Result<ParsedChain> {
    use pbmx_blocks::block::Payload::*;

    if chain.is_empty() {
        return Ok(ParsedChain {
            name: String::new(),
            group: None,
            vtmf: None,
            stacks: StackMap::new(),
        });
    }

    let mut state = ParseState::default();
    state.private_key = private_key.clone();
    for block in chain.blocks() {
        for payload in block.payloads() {
            match payload {
                DefineGame(d, g) => {
                    state.set_name(d.clone())?;
                    state.set_group(g.clone())?;
                }
                PublishKey(pk) => {
                    state.add_key(pk.clone())?;
                }
                // NameStack(id, n) => {
                //    state.name_stack(*id, n)?;
                //}
                _ => {}
            }
        }
    }
    if state.vtmf.is_none() {
        return Err(Error::BadGenesis);
    }
    let mut stack_map = StackMap::new();
    for stack in state.stacks.iter() {
        stack_map.insert(stack.clone());
    }
    for (name, id) in state.stack_names.iter() {
        stack_map.set_name_id(id, name.clone());
    }
    Ok(ParsedChain {
        name: state.name,
        group: state.group,
        vtmf: state.vtmf,
        stacks: stack_map,
    })
}

impl ParseState {
    fn set_name(&mut self, s: String) -> Result<()> {
        if !self.name.is_empty() {
            return Err(Error::BadGenesis);
        }
        self.name = s;
        Ok(())
    }

    fn set_group(&mut self, g: Group) -> Result<()> {
        if self.group.is_some() || self.vtmf.is_some() {
            return Err(Error::BadGenesis);
        }
        self.group = Some(g);
        Ok(())
    }

    fn add_key(&mut self, pk: PublicKey) -> Result<()> {
        if let Some(sk) = &self.private_key {
            if pk.fingerprint() == sk.fingerprint() {
                self.vtmf = Some(Vtmf::new(sk.clone()));
                return Ok(());
            }
        }
        Ok(())
        //        if self.kex.is_none() {
        //            return Err(Error::BadGenesis);
        //        }
        //        let rkex = self.kex.as_mut().unwrap();
        //        rkex.update_key(pk)?;
        //        if rkex.has_all_keys() {
        //            self.vtmf = Some(self.kex.take().unwrap().finalize()?);
        //        }
        //        Ok(())
    }

    //    fn add_stack(&mut self, stack: Vec<Mask>) -> Result<()> {
    //        self.stacks.push(stack.into());
    //        Ok(())
    //    }
    //
    //    fn name_stack(&mut self, id: Id, name: &str) -> Result<()> {
    //        self.stack_names
    //            .entry(name.into())
    //            .and_modify(|e| *e = id)
    //            .or_insert(id);
    //        Ok(())
    //    }
    //
    //    fn verify_shuffle(&mut self, id1: &Id, id2: &Id, proof: &ShuffleProof) ->
    // Result<()> {        if self.vtmf.is_none() {
    //            return Err(Error::BadGenesis);
    //        }
    //
    //        let vtmf = self.vtmf.as_ref().unwrap();
    //
    //        let s1 = self.stacks.iter().find(|s| s.id() == *id1).unwrap();
    //        let s2 = self.stacks.iter().find(|s| s.id() == *id2).unwrap();
    //        if !vtmf.verify_mask_shuffle(s1.tokens(), s2.tokens(), proof) {
    //            return Err(Error::InvalidProof);
    //        }
    //        Ok(())
    //    }
}
