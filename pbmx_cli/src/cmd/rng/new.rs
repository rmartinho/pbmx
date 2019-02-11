use crate::{state::State, Config, Error, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::payload::Payload;
use rand::thread_rng;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;
    let bound = value_t!(m, "BOUND", u64)?;

    let mut state = State::read(true)?;

    if state.rngs.contains_key(&name) {
        return Err(Error::InvalidData);
    }

    println!(
        "{} {} < {}",
        " + Random number generator".green().bold(),
        name,
        bound
    );
    state
        .payloads
        .push(Payload::RandomBound(name.clone(), bound));

    let mask = state.vtmf.mask_random(&mut thread_rng());

    println!("{} {}", " + Entropy".green().bold(), name);
    state.payloads.push(Payload::RandomEntropy(name, mask));

    state.save_payloads()?;
    Ok(())
}
