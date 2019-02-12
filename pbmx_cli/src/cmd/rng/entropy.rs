use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use rand::thread_rng;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;

    let mut state = State::read(true)?;

    let fp = state.vtmf.private_key().fingerprint();
    let rng = state.rngs.get(&name).ok_or(Error::InvalidData)?;
    if rng.entropy_parties().contains(&fp) {
        return Err(Error::InvalidData);
    }

    let mask = state.vtmf.mask_random(&mut thread_rng());

    println!("{} {}", " + Entropy".green().bold(), name);
    state.payloads.push(Payload::RandomEntropy(name, mask));

    state.save_payloads()?;
    Ok(())
}
