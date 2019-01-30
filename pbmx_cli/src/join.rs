use crate::{constants::VTMF_FILE_NAME, error::Result, file};
use clap::{value_t, ArgMatches};
use pbmx_curve::keys::PrivateKey;
use pbmx_curve::vtmf::Vtmf;
use rand::thread_rng;
use std::{fs, str, path::PathBuf};

pub fn join(m: &ArgMatches) -> Result<()> {
    let vtmf = str::parse::<Vtmf>(&fs::read_to_string(VTMF_FILE_NAME)?)?;
    Ok(())
}

