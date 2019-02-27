use crate::{random::Rng, state::State, Config, Error, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::chain::payload::Payload;
use rand::thread_rng;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;
    let spec = value_t!(m, "SPEC", String)?;

    let mut state = State::read(true)?;

    if state.rngs.contains_key(&name) {
        return Err(Error::InvalidData);
    }

    let _ = Rng::new(state.vtmf.parties(), &spec)?;
    println!(
        "{} {}: {}",
        " + Random number generator".green().bold(),
        name,
        spec
    );
    state.payloads.push(Payload::RandomSpec(name.clone(), spec));

    let mask = state.vtmf.mask_random(&mut thread_rng());

    println!("{} {}", " + Entropy".green().bold(), name);
    state.payloads.push(Payload::RandomEntropy(name, mask));

    state.save_payloads()?;
    Ok(())
}
