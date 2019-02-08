use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;

pub fn reveal(m: &ArgMatches, _: &Config) -> Result<()> {
    let mut state = State::read(true)?;

    let id = value_t!(m, "STACK", String)?;
    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;

    let (s, p): (Vec<_>, Vec<_>) = stack.iter().map(|m| state.vtmf.unmask_share(m)).unzip();

    let id1 = stack.id();
    state.payloads.push(Payload::PublishShares(id1, s, p));
    println!("{} {:16}", " + Publish secrets".green().bold(), id1,);

    state.save_payloads()?;
    Ok(())
}
