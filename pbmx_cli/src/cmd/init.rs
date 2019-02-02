use crate::{
    constants::{BLOCKS_FOLDER_NAME, CURRENT_BLOCK_FILE_NAME, KEY_FILE_NAME, SECRETS_FOLDER_NAME},
    error::Result,
    file,
};
use clap::{value_t, ArgMatches};
use pbmx_chain::payload::Payload;
use pbmx_curve::keys::PrivateKey;
use pbmx_serde::ToBase64;
use rand::thread_rng;
use std::{fs, path::PathBuf};

pub fn init(m: &ArgMatches) -> Result<()> {
    let mut path = value_t!(m, "PATH", PathBuf)?;

    let mut rng = thread_rng();
    let sk = PrivateKey::random(&mut rng);
    let current = <Vec<Payload>>::new();

    fs::create_dir_all(&path)?;

    {
        path.push(BLOCKS_FOLDER_NAME);
        fs::create_dir_all(&path)?;
        path.pop();
    }

    {
        path.push(CURRENT_BLOCK_FILE_NAME);
        file::write_new(&path, &current.to_base64()?.as_bytes())?;
        path.pop();
    }

    {
        path.push(SECRETS_FOLDER_NAME);
        fs::create_dir_all(&path)?;
        {
            path.push(KEY_FILE_NAME);
            file::write_new(&path, &sk.to_base64()?.as_bytes())?;
            path.pop();
        }
        path.pop();
    }

    Ok(())
}
