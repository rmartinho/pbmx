use crate::{error::Result, file};
use clap::{value_t, ArgMatches};
use pbmx_curve::keys::PrivateKey;
use rand::thread_rng;
use std::{fs, path::PathBuf};

pub fn init(m: &ArgMatches) -> Result<()> {
    let path = value_t!(m, "PATH", PathBuf)?;

    fs::create_dir_all(&path)?;

    let mut rng = thread_rng();
    let sk = PrivateKey::random(&mut rng);

    let mut key_path = path.clone();
    key_path.push("secret.pbmx");
    file::write_new(key_path, &sk.to_string().as_bytes())?;
    Ok(())
}
