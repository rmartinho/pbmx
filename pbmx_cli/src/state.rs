use crate::{
    constants::{BLOCKS_FOLDER_NAME, BLOCK_EXTENSION, CURRENT_BLOCK_FILE_NAME, KEY_FILE_NAME},
    error::Result,
    secrets::SecretMap,
    stacks::StackMap,
};
use pbmx_chain::{
    block::Block,
    chain::{Chain, ChainVisitor},
    payload::Payload,
    Id,
};
use pbmx_curve::{
    keys::{PrivateKey, PublicKey},
    vtmf::{
        Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
        Vtmf,
    },
};
use pbmx_serde::{FromBase64, ToBase64};
use std::{ffi::OsStr, fs};

#[derive(Debug)]
pub struct State {
    pub vtmf: Vtmf,
    pub chain: Chain,
    pub stacks: StackMap,
    pub secrets: SecretMap,
    pub payloads: Vec<Payload>,
}

impl State {
    pub fn read() -> Result<State> {
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

        let sk = PrivateKey::from_base64(&fs::read_to_string(KEY_FILE_NAME)?)?;
        let mut visitor = ChainParser {
            vtmf: Vtmf::new(sk),
            stacks: StackMap::new(),
            secrets: SecretMap::new(),
        };
        chain.visit(&mut visitor);

        let payloads = Vec::from_base64(&fs::read_to_string(CURRENT_BLOCK_FILE_NAME)?)?;

        Ok(State {
            vtmf: visitor.vtmf,
            stacks: visitor.stacks,
            secrets: visitor.secrets,
            chain,
            payloads,
        })
    }

    pub fn clear_payloads(&mut self) {
        self.payloads.clear();
    }

    pub fn save_payloads(&self) -> Result<()> {
        fs::write(
            CURRENT_BLOCK_FILE_NAME,
            &self.payloads.to_base64()?.as_bytes(),
        )?;
        Ok(())
    }
}

struct ChainParser {
    vtmf: Vtmf,
    stacks: StackMap,
    secrets: SecretMap,
}

impl ChainVisitor for ChainParser {
    fn visit_publish_key(&mut self, _: &Chain, _: &Block, pk: &PublicKey) {
        self.vtmf.add_key(pk.clone()).unwrap();
    }

    fn visit_open_stack(&mut self, _: &Chain, _: &Block, stack: &[Mask]) {
        self.stacks.insert(stack.to_vec());
    }

    fn visit_private_stack(
        &mut self,
        _: &Chain,
        _: &Block,
        _: Id,
        stack: &[Mask],
        _: &[PrivateMaskProof],
    ) {
        self.stacks.insert(stack.to_vec());
    }

    fn visit_mask_stack(&mut self, _: &Chain, _: &Block, _: Id, stack: &[Mask], _: &[MaskProof]) {
        self.stacks.insert(stack.to_vec());
    }

    fn visit_shuffle_stack(
        &mut self,
        _: &Chain,
        _: &Block,
        _: Id,
        stack: &[Mask],
        _: &ShuffleProof,
    ) {
        self.stacks.insert(stack.to_vec());
    }

    fn visit_shift_stack(&mut self, _: &Chain, _: &Block, _: Id, stack: &[Mask], _: &ShiftProof) {
        self.stacks.insert(stack.to_vec());
    }

    fn visit_name_stack(&mut self, _: &Chain, _: &Block, id: Id, name: &str) {
        self.stacks.set_name(id, name.to_string());
    }

    fn visit_publish_shares(
        &mut self,
        _: &Chain,
        block: &Block,
        id: Id,
        shares: &[SecretShare],
        _: &[SecretShareProof],
    ) {
        self.secrets.insert(id, block.signer(), shares.to_vec());
    }
}
