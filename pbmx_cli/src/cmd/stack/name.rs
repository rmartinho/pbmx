use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_kit::chain::Payload;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;
    let id = value_t!(m, "ID", String)?;

    let mut state = State::read(true)?;

    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;

    let id = stack.id();
    println!("{} {:16} {}", " + Name stack".green().bold(), id, name);
    state.payloads.push(Payload::NameStack(id, name));

    state.save_payloads()?;
    Ok(())
}
