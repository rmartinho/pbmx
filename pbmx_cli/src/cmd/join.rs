use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::chain::Payload;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String)?;

    let mut state = State::read(false)?;

    let key = state.vtmf.public_key();
    let fp = key.fingerprint();

    println!("{} {} {}", " + Publish key ".green().bold(), &name, fp);
    state.payloads.push(Payload::PublishKey(name, key));

    state.save_payloads()?;
    Ok(())
}
