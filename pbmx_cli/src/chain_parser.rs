use crate::{
    error::{Error, Result},
    stacks::{Stack, StackMap},
};
use pbmx_blocks::{block::Id, chain::Chain};
use pbmx_crypto::{
    group::Group,
    keys::{PrivateKey, PublicKey},
    vtmf::{ShuffleProof, KeyExchange, Mask, Vtmf},
};
use std::collections::HashMap;

#[allow(clippy::large_enum_variant)]
pub enum ParsedChain {
    Empty,
    ExchangingKeys(String, KeyExchange),
    KeysExchanged(String, Vtmf, StackMap),
}

impl ParsedChain {
    pub fn name(&self) -> Option<&str> {
        match self {
            ParsedChain::ExchangingKeys(n, _) => Some(n),
            ParsedChain::KeysExchanged(n, ..) => Some(n),
            _ => None,
        }
    }

    pub fn group(&self) -> Option<&Group> {
        match self {
            ParsedChain::ExchangingKeys(_, kex) => Some(kex.group()),
            ParsedChain::KeysExchanged(_, vtmf, ..) => Some(vtmf.group()),
            _ => None,
        }
    }

    pub fn parties(&self) -> Option<u32> {
        match self {
            ParsedChain::ExchangingKeys(_, kex) => Some(kex.parties()),
            ParsedChain::KeysExchanged(_, vtmf, ..) => Some(vtmf.parties()),
            _ => None,
        }
    }

    pub fn vtmf(&self) -> Option<&Vtmf> {
        match self {
            ParsedChain::KeysExchanged(_, vtmf, ..) => Some(vtmf),
            _ => None,
        }
    }

    pub fn stacks(&self) -> Option<&StackMap> {
        match self {
            ParsedChain::KeysExchanged(_, _, stacks) => Some(stacks),
            _ => None,
        }
    }

    pub fn print_out(&self) {
        if let ParsedChain::Empty = self {
            return;
        }
        println!(
            "# Game: {} {}p",
            self.name().unwrap(),
            self.parties().unwrap()
        );
        if let Some(stacks) = self.stacks() {
            for (n, s) in stacks.named_stacks() {
                println!("# Stack {} [{:16}]:\n\t{}", n, s.id(), s);
            }
        }
    }
}

#[derive(Default)]
struct ParseState {
    name: String,
    parties: u32,
    group: Option<Group>,
    private_key: Option<PrivateKey>,
    kex: Option<KeyExchange>,
    vtmf: Option<Vtmf>,
    stacks: Vec<Stack>,
    stack_names: HashMap<String, Id>,
}

pub fn parse_chain(chain: &Chain, private_key: &Option<PrivateKey>) -> Result<ParsedChain> {
    use pbmx_blocks::block::Payload::*;

    if chain.is_empty() {
        return Ok(ParsedChain::Empty);
    }

    let mut state = ParseState::default();
    state.private_key = private_key.clone();
    for block in chain.blocks() {
        for payload in block.payloads() {
            match payload {
                DefineGame(g, n) => {
                    state.set_name(g.clone())?;
                    state.set_parties(*n)?;
                }
                PublishGroup(g) => {
                    state.set_group(g.clone())?;
                }
                PublishKey(pk) => {
                    state.add_key(pk.clone())?;
                }
                CreateStack(s) => {
                    state.add_stack(s.clone())?;
                }
                NameStack(id, n) => {
                    state.name_stack(*id, n)?;
                }
                ProveShuffle(id1, id2, p) => {
                    state.verify_shuffle(id1, id2, p).unwrap();
                }
                _ => {}
            }
        }
    }
    if state.kex.is_none() && state.vtmf.is_none() {
        return Err(Error::BadGenesis);
    }
    if let Some(kex) = state.kex.take() {
        Ok(ParsedChain::ExchangingKeys(state.name, kex))
    } else {
        let mut stack_map = StackMap::new();
        for stack in state.stacks.iter() {
            stack_map.insert(stack.clone());
        }
        for (name, id) in state.stack_names.iter() {
            stack_map.set_name_id(id, name.clone());
        }
        Ok(ParsedChain::KeysExchanged(
            state.name,
            state.vtmf.unwrap(),
            stack_map,
        ))
    }
}

impl ParseState {
    fn set_name(&mut self, s: String) -> Result<()> {
        if !self.name.is_empty() {
            return Err(Error::BadGenesis);
        }
        self.name = s;
        Ok(())
    }

    fn set_parties(&mut self, n: u32) -> Result<()> {
        if self.parties > 0 {
            return Err(Error::BadGenesis);
        }
        self.parties = n;
        if let Some(g) = self.group.take() {
            let mut kex = KeyExchange::new(g, n);
            if let Some(sk) = &self.private_key {
                kex.use_private_key(sk.clone())?;
            } else {
                kex.generate_key()?;
            }
            self.kex = Some(kex);
        }
        Ok(())
    }

    fn set_group(&mut self, g: Group) -> Result<()> {
        if self.group.is_some() || self.kex.is_some() {
            return Err(Error::BadGenesis);
        }
        if self.parties > 0 {
            let mut kex = KeyExchange::new(g, self.parties);
            if let Some(sk) = &self.private_key {
                kex.use_private_key(sk.clone())?;
            } else {
                kex.generate_key()?;
            }
            self.kex = Some(kex);
        } else {
            self.group = Some(g);
        }
        Ok(())
    }

    fn add_key(&mut self, pk: PublicKey) -> Result<()> {
        if Some(&pk) == self.private_key.as_ref().map(|sk| sk.public_key()).as_ref() {
            return Ok(());
        }
        if self.kex.is_none() {
            return Err(Error::BadGenesis);
        }
        let rkex = self.kex.as_mut().unwrap();
        rkex.update_key(pk)?;
        if rkex.has_all_keys() {
            self.vtmf = Some(self.kex.take().unwrap().finalize()?);
        }
        Ok(())
    }

    fn add_stack(&mut self, stack: Vec<Mask>) -> Result<()> {
        self.stacks.push(stack.into());
        Ok(())
    }

    fn name_stack(&mut self, id: Id, name: &str) -> Result<()> {
        self.stack_names
            .entry(name.into())
            .and_modify(|e| *e = id)
            .or_insert(id);
        Ok(())
    }

    fn verify_shuffle(&mut self, id1: &Id, id2: &Id, proof: &ShuffleProof) -> Result<()> {
        if self.vtmf.is_none() {
            return Err(Error::BadGenesis);
        }

        let vtmf = self.vtmf.as_ref().unwrap();

        let s1 = self.stacks.iter().find(|s| s.id() == *id1).unwrap();
        let s2 = self.stacks.iter().find(|s| s.id() == *id2).unwrap();
        if !vtmf.verify_mask_shuffle(s1.tokens(), s2.tokens(), proof) {
            return Err(Error::InvalidProof);
        }
        Ok(())
    }
}
