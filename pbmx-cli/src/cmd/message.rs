use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use pbmx_kit::chain::Payload;
use std::{fs, path::PathBuf};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let text = if let Ok(string) = value_t!(m, "MESSAGE", String) {
        string
    } else if let Ok(path) = value_t!(m, "FILE", PathBuf) {
        fs::read_to_string(path)?
    } else {
        return Err(Error::InvalidData);
    };

    let mut state = State::read(false)?;

    state.payloads.push(Payload::Text(text));

    state.save_payloads()?;
    Ok(())
}
