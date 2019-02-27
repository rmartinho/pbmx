use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_kit::chain::Payload;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;

    let mut state = State::read(true)?;

    let fp = state.vtmf.private_key().fingerprint();
    let rng = state.rngs.get(&name).ok_or(Error::InvalidData)?;
    if rng.secret_parties().contains(&fp) {
        return Err(Error::InvalidData);
    }

    let (share, proof) = state.vtmf.unmask_share(rng.mask());

    println!("{} {}", " + Random number secret".green().bold(), name);
    state
        .payloads
        .push(Payload::RandomReveal(name, share, proof));

    state.save_payloads()?;
    Ok(())
}
