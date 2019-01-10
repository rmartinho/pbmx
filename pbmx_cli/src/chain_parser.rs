use crate::error::{Error, Result};
use pbmx_blocks::{block::Id, chain::Chain};
use pbmx_crypto::{
    group::Group,
    keys::{PrivateKey, PublicKey},
    vtmf::{KeyExchange, Mask, Vtmf},
};
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};

#[allow(clippy::large_enum_variant)]
pub enum ParsedChain {
    Empty,
    ExchangingKeys(String, KeyExchange),
    KeysExchanged(String, Vtmf, Vec<(Id, Vec<Mask>)>, HashMap<String, Id>),
}

const NO_STACKS: [(Id, Vec<Mask>); 0] = [];

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

    pub fn stacks(&self) -> &[(Id, Vec<Mask>)] {
        match self {
            ParsedChain::KeysExchanged(_, _, stacks, _) => &stacks,
            _ => &NO_STACKS,
        }
    }

    pub fn stack_names(&self) -> Option<&HashMap<String, Id>> {
        match self {
            ParsedChain::KeysExchanged(_, _, _, names) => Some(&names),
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
        if let Some(names) = self.stack_names() {
            for (n, id) in names.iter() {
                let (i, s) = self
                    .stacks()
                    .iter()
                    .enumerate()
                    .find_map(|(i, (id1, s))| if id1 == id { Some((i, s)) } else { None })
                    .unwrap();
                println!("# Stack {} #{} [{:16}]:\n\t{}", n, i, id, StackDisplay(s));
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
    stacks: Vec<(Id, Vec<Mask>)>,
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
                    state.add_stack(payload.id(), s.clone())?;
                }
                NameStack(id, n) => {
                    state.name_stack(*id, n)?;
                }
                _ => {}
            }
        }
    }
    if state.kex.is_none() && state.vtmf.is_none() {
        println!("aaa");
        return Err(Error::BadGenesis);
    }
    if let Some(kex) = state.kex.take() {
        Ok(ParsedChain::ExchangingKeys(state.name, kex))
    } else {
        Ok(ParsedChain::KeysExchanged(
            state.name,
            state.vtmf.unwrap(),
            state.stacks,
            state.stack_names,
        ))
    }
}

impl ParseState {
    fn set_name(&mut self, s: String) -> Result<()> {
        if !self.name.is_empty() {
            println!("qux");
            return Err(Error::BadGenesis);
        }
        self.name = s;
        Ok(())
    }

    fn set_parties(&mut self, n: u32) -> Result<()> {
        if self.parties > 0 {
            println!("foo");
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
            println!("bar");
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
            println!("kux");
            return Err(Error::BadGenesis);
        }
        let rkex = self.kex.as_mut().unwrap();
        rkex.update_key(pk)?;
        if rkex.has_all_keys() {
            self.vtmf = Some(self.kex.take().unwrap().finalize()?);
        }
        Ok(())
    }

    fn add_stack(&mut self, id: Id, stack: Vec<Mask>) -> Result<()> {
        self.stacks.push((id, stack));
        Ok(())
    }

    fn name_stack(&mut self, id: Id, name: &str) -> Result<()> {
        self.stack_names
            .entry(name.into())
            .and_modify(|e| *e = id)
            .or_insert(id);
        Ok(())
    }
}

struct StackDisplay<'a>(&'a Vec<Mask>);

impl<'a> Display for StackDisplay<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut last_encrypted = 0;
        write!(f, "[")?;
        let mut comma = false;
        for (c1, c2) in self.0.iter() {
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
