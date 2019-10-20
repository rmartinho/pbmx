use crate::{
    constants::{
        BLOCKS_FOLDER_NAME, BLOCK_EXTENSION, CURRENT_BLOCK_FILE_NAME, KEY_FILE_NAME,
        SECRETS_FOLDER_NAME, SECRET_EXTENSION,
    },
    Error, Result,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use pbmx_kit::{
    chain::{Block, Payload},
    crypto::{
        keys::PrivateKey,
        vtmf::{Mask, Stack},
    },
    serde::Message,
    state::{PrivateSecretMap, State as BaseState},
};
use std::{ffi::OsStr, fs, path::PathBuf};

#[derive(Debug)]
pub struct State {
    pub base: BaseState,
    pub payloads: Vec<Payload>,
}

impl State {
    pub fn read(include_temp: bool) -> Result<State> {
        let mut path = PathBuf::from(SECRETS_FOLDER_NAME);
        path.push(KEY_FILE_NAME);
        let sk = PrivateKey::decode(&fs::read(&path)?)?;

        let mut base = BaseState::new(sk.clone());
        for entry in fs::read_dir(BLOCKS_FOLDER_NAME)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let block_extension = OsStr::new(BLOCK_EXTENSION);
            if let Some(ext) = entry.path().extension() {
                if ext != block_extension {
                    continue;
                }
                let block = Block::decode(&fs::read(&entry.path())?)?;
                base.add_block(&block).map_err(|_| Error::InvalidBlock)?;
            }
        }

        for entry in fs::read_dir(SECRETS_FOLDER_NAME)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let secret_extension = OsStr::new(SECRET_EXTENSION);
            if let Some(ext) = entry.path().extension() {
                if ext != secret_extension {
                    continue;
                }
                let secrets = PrivateSecretMap::decode(&fs::read(&entry.path())?)?;
                base.add_secrets(secrets.into_iter())
                    .map_err(|_| Error::InvalidBlock)?;
            }
        }

        let payloads = Vec::decode(&fs::read(CURRENT_BLOCK_FILE_NAME)?)?;

        if include_temp {
            let mut builder = base.chain.build_block();
            for p in payloads.iter().cloned() {
                builder.add_payload(p);
            }
            let block = builder.build(&sk);
            base.add_block(&block).map_err(|_| Error::InvalidBlock)?;
        }

        Ok(State { base, payloads })
    }

    pub fn clear_payloads(&mut self) {
        self.payloads.clear();
    }

    pub fn save_secrets(&self, stack: &Stack, secrets: Vec<Scalar>) -> Result<()> {
        let base_mask = Mask(
            RISTRETTO_BASEPOINT_POINT,
            self.base.vtmf.shared_key().point(),
        );
        let map: PrivateSecretMap = stack
            .iter()
            .cloned()
            .zip(secrets.into_iter())
            .map(|(m, r)| (m, r * base_mask))
            .collect();

        let secret_file = format!("{}.{}", stack.id(), SECRET_EXTENSION);
        let mut path = PathBuf::from(SECRETS_FOLDER_NAME);
        path.push(secret_file);
        fs::write(path, &map.encode()?)?;
        Ok(())
    }

    pub fn save_payloads(&self) -> Result<()> {
        fs::write(CURRENT_BLOCK_FILE_NAME, &self.payloads.encode()?)?;
        Ok(())
    }
}
