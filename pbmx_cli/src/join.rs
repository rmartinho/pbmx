use crate::{error::Result, state::State};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::payload::Payload;
use std::io::{stdout, Write};

pub fn join(_: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    print!("{}", " + Publish key ".green().bold());
    stdout().flush()?;

    let key = state.vtmf.public_key();
    let fp = key.fingerprint();
    state.payloads.push(Payload::PublishKey(key));
    println!("{}", fp);

    state.save_payloads()?;
    Ok(())
}
