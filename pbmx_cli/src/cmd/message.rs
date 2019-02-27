use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use pbmx_kit::chain::payload::Payload;
use std::{fs, path::PathBuf};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let data = if let Ok(string) = value_t!(m, "MESSAGE", String) {
        string.into_bytes()
    } else if let Ok(bin) = value_t!(m, "BASE64", String) {
        base64::decode_config(&bin, base64::URL_SAFE_NO_PAD)
            .map_err(pbmx_kit::serde::Error::from)?
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
