use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;

    let state = State::read(true)?;

    let rng = state.rngs.get(&name).ok_or(Error::InvalidData)?;
    if rng.entropy_parties().len() < state.vtmf.parties()
        || rng.secret_parties().len() < state.vtmf.parties()
    {
        return Err(Error::InvalidData);
    }

    let n = rng.gen(&state.vtmf);
    println!("{} {} = {}", " - Random".green().bold(), name, n);

    Ok(())
}
