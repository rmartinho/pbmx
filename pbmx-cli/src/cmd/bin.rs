use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use pbmx_kit::chain::Payload;
use std::{fs, path::PathBuf};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let data = if let Ok(string) = value_t!(m, "DATA", String) {
        base64::decode_config(&string, base64::URL_SAFE_NO_PAD)
            .map_err(|_| pbmx_kit::Error::Decoding)?
    } else if let Ok(path) = value_t!(m, "FILE", PathBuf) {
        fs::read(path)?
    } else {
        return Err(Error::InvalidData);
    };

    let mut state = State::read(false)?;

    state.payloads.push(Payload::Bytes(data));

    state.save_payloads()?;
    Ok(())
}
