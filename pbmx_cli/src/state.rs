use crate::{
    constants::{BLOCKS_FOLDER_NAME, BLOCK_EXTENSION, CURRENT_BLOCK_FILE_NAME, KEY_FILE_NAME},
    error::Result,
    stacks::StackMap,
};
use pbmx_chain::{block::Block, chain::Chain, payload::Payload};
use pbmx_curve::{keys::PrivateKey, vtmf::Vtmf};
use pbmx_serde::{FromBase64, ToBase64};
use std::{ffi::OsStr, fs};

#[derive(Debug)]
pub struct State {
    pub vtmf: Vtmf,
    pub chain: Chain,
    pub stacks: StackMap,
    pub payloads: Vec<Payload>,
}

impl State {
    pub fn read() -> Result<State> {
        use Payload::*;

        let sk = PrivateKey::from_base64(&fs::read_to_string(KEY_FILE_NAME)?)?;
        let mut vtmf = Vtmf::new(sk);

        let mut chain = Chain::new();
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
                let block = Block::from_base64(&fs::read_to_string(&entry.path())?)?;
                chain.add_block(block);
            }
        }

        let mut stacks = StackMap::new();
        for block in chain.blocks() {
            for payload in block.payloads() {
                match payload {
                    PublishKey(pk) => {
                        vtmf.add_key(pk.clone())?;
                    }
                    OpenStack(stk) => {
                        stacks.insert(stk.clone());
                    }
                    PrivateStack(_, stk, _) => {
                        stacks.insert(stk.clone());
                    }
                    MaskStack(_, stk, _) => {
                        stacks.insert(stk.clone());
                    }
                    ShuffleStack(_, stk, _) => {
                        stacks.insert(stk.clone());
                    }
                    ShiftStack(_, stk, _) => {
                        stacks.insert(stk.clone());
                    }
                    NameStack(id, name) => {
                        stacks.set_name(name.clone(), *id);
                    }
                    // PublishShares(Id, Vec<SecretShare>, Vec<SecretShareProof>),
                    // StartRandom(u64),
                    // RandomShare(Id, Mask),
                    // Bytes(Vec<u8>),
                    _ => {}
                }
            }
        }

        let payloads = Vec::from_base64(&fs::read_to_string(CURRENT_BLOCK_FILE_NAME)?)?;

        Ok(State {
            vtmf,
            chain,
            stacks,
            payloads,
        })
    }

    pub fn save_payloads(&self) -> Result<()> {
        fs::write(
            CURRENT_BLOCK_FILE_NAME,
            &self.payloads.to_base64()?.as_bytes(),
        )?;
        Ok(())
    }
}
