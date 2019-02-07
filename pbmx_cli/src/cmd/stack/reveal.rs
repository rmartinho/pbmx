use crate::{
    error::{Error, Result},
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;

pub fn reveal(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let id = value_t!(m, "STACK", String)?;
    let e = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;

    let (s, p): (Vec<_>, Vec<_>) = e.stack.iter().map(|m| state.vtmf.unmask_share(m)).unzip();

    let id1 = e.stack.id();
    state.payloads.push(Payload::PublishShares(id1, s, p));
    println!("{} {:16}", " + Publish secrets".green().bold(), id1,);

    state.save_payloads()?;
    Ok(())
}
