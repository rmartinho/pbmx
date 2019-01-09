use crate::error::{Error, Result};
use pbmx_blocks::chain::Chain;
use pbmx_crypto::{
    group::Group,
    keys::{PrivateKey, PublicKey},
    vtmf::{KeyExchange, Vtmf},
};

#[allow(clippy::large_enum_variant)]
pub enum ParsedChain {
    Empty,
    ExchangingKeys(String, KeyExchange),
    KeysExchanged(String, Vtmf),
}

impl ParsedChain {
    pub fn name(&self) -> Option<&str> {
        match self {
            ParsedChain::ExchangingKeys(n, _) => Some(n),
            ParsedChain::KeysExchanged(n, _) => Some(n),
            ParsedChain::Empty => None,
        }
    }

    pub fn group(&self) -> Option<Group> {
        match self {
            ParsedChain::ExchangingKeys(_, kex) => Some(kex.group().clone()),
            ParsedChain::KeysExchanged(_, vtmf) => Some(vtmf.group().clone()),
            ParsedChain::Empty => None,
        }
    }

    pub fn parties(&self) -> Option<u32> {
        match self {
            ParsedChain::ExchangingKeys(_, kex) => Some(kex.parties()),
            ParsedChain::KeysExchanged(_, vtmf) => Some(vtmf.parties()),
            ParsedChain::Empty => None,
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
        Ok(ParsedChain::KeysExchanged(state.name, state.vtmf.unwrap()))
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
}
