use crate::{constants::VTMF_FILE_NAME, error::Result};
use clap::ArgMatches;
use pbmx_curve::vtmf::Vtmf;
use pbmx_serde::FromBase64;
use std::fs;

pub fn join(m: &ArgMatches) -> Result<()> {
    let vtmf = Vtmf::from_base64(&fs::read_to_string(VTMF_FILE_NAME)?)?;
    Ok(())
}
