use crate::{constants::VTMF_FILE_NAME, error::Result, file};
use clap::{value_t, ArgMatches};
use pbmx_curve::{keys::PrivateKey, vtmf::Vtmf};
use pbmx_serde::ToBase64;
use rand::thread_rng;
use std::{fs, path::PathBuf};

pub fn init(m: &ArgMatches) -> Result<()> {
    let path = value_t!(m, "PATH", PathBuf)?;

    fs::create_dir_all(&path)?;

    let mut rng = thread_rng();
    let sk = PrivateKey::random(&mut rng);
    let vtmf = Vtmf::new(sk);

    let mut vtmf_path = path.clone();
    vtmf_path.push(VTMF_FILE_NAME);
    file::write_new(vtmf_path, &vtmf.to_base64()?.as_bytes())?;
    Ok(())
}
