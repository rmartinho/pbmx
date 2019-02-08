use crate::{
    error::{Error, Result},
    state::State,
};
use clap::{value_t, ArgMatches};
use pbmx_chain::payload::Payload;
use std::{fs, path::PathBuf};

pub fn message(m: &ArgMatches) -> Result<()> {
    let mut state = State::read(false)?;

    let data = if let Ok(string) = value_t!(m, "MESSAGE", String) {
        string.into_bytes()
    } else if let Ok(bin) = value_t!(m, "BASE64", String) {
        base64::decode_config(&bin, base64::URL_SAFE_NO_PAD).map_err(pbmx_serde::Error::from)?
    } else if let Ok(path) = value_t!(m, "FILE", PathBuf) {
        fs::read(path)?
    } else {
        return Err(Error::InvalidData);
    };

    state.payloads.push(Payload::Bytes(data));

    state.save_payloads()?;
    Ok(())
}
