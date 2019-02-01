use crate::{error::Result, state::State};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::payload::Payload;

pub fn join(_: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let key = state.vtmf.public_key();
    let fp = key.fingerprint();
    state.payloads.push(Payload::PublishKey(key));

    println!("{} {}", " + Publish key ".green().bold(), fp);

    state.save_payloads()?;
    Ok(())
}
