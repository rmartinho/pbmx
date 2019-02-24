use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;
    let count = value_t!(m, "COUNT", usize).unwrap_or(1);

    let state = State::read(false)?;

    let rng = state.rngs.get(&name).ok_or(Error::InvalidData)?;
    if rng.entropy_parties().len() < state.vtmf.parties()
        || rng.secret_parties().len() < state.vtmf.parties()
    {
        return Err(Error::InvalidData);
    }

    let numbers = rng.gen(&state.vtmf);

    for n in numbers.take(count) {
        println!("{} {} = {}", " - Random".green().bold(), name, n);
    }

    Ok(())
}
