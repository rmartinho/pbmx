use crate::{
    constants::{
        BLOCKS_FOLDER_NAME, CONFIG_FILE_CONTENTS, CONFIG_FILE_NAME, CURRENT_BLOCK_FILE_NAME,
        IGNORE_FILE_CONTENTS, IGNORE_FILE_NAME, KEY_FILE_NAME, SECRETS_FOLDER_NAME,
    },
    file, Config, Result,
};
use clap::{value_t, ArgMatches};
use pbmx_kit::{chain::Payload, crypto::keys::PrivateKey, serde::Message};
use rand::thread_rng;
use std::{fs, path::PathBuf};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let mut path = value_t!(m, "PATH", PathBuf).unwrap_or_else(|_| PathBuf::from("."));

    let mut rng = thread_rng();
    let sk = PrivateKey::random(&mut rng);
    let current = <Vec<Payload>>::new();

    fs::create_dir_all(&path)?;

    {
        path.push(IGNORE_FILE_NAME);
        file::write_new(&path, IGNORE_FILE_CONTENTS)?;
        path.pop();
    }

    {
        path.push(CONFIG_FILE_NAME);
        file::write_new(&path, CONFIG_FILE_CONTENTS)?;
        path.pop();
    }

    {
        path.push(BLOCKS_FOLDER_NAME);
        fs::create_dir_all(&path)?;
        path.pop();
    }

    {
        path.push(CURRENT_BLOCK_FILE_NAME);
        file::write_new(&path, &current.encode()?)?;
        path.pop();
    }

    {
        path.push(SECRETS_FOLDER_NAME);
        fs::create_dir_all(&path)?;
        {
            path.push(KEY_FILE_NAME);
            file::write_new(&path, &sk.encode()?)?;
            path.pop();
        }
        path.pop();
    }

    Ok(())
}
