use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::payload::Payload;

pub fn run(_: &ArgMatches, _: &Config) -> Result<()> {
    let mut state = State::read(false)?;

    let key = state.vtmf.public_key();
    let fp = key.fingerprint();
    state.payloads.push(Payload::PublishKey(key));

    println!("{} {}", " + Publish key ".green().bold(), fp);

    state.save_payloads()?;
    Ok(())
}
