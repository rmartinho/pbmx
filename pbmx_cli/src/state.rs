use crate::{
    constants::{
        BLOCKS_FOLDER_NAME, BLOCK_EXTENSION, CURRENT_BLOCK_FILE_NAME, KEY_FILE_NAME,
        SECRETS_FOLDER_NAME,
    },
    error::Result,
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
    vtmf::{MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof, Stack, Vtmf},
};
use pbmx_serde::{FromBase64, ToBase64};
use std::{ffi::OsStr, fs, path::PathBuf};

#[derive(Debug)]
pub struct State {
    pub vtmf: Vtmf,
    pub chain: Chain,
    pub stacks: StackMap,
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

        let payloads = Vec::from_base64(&fs::read_to_string(CURRENT_BLOCK_FILE_NAME)?)?;

        let mut path = PathBuf::from(SECRETS_FOLDER_NAME);
        path.push(KEY_FILE_NAME);
        let sk = PrivateKey::from_base64(&fs::read_to_string(&path)?)?;
        let mut visitor = ChainParser {
            vtmf: Vtmf::new(sk),
            stacks: StackMap::new(),
        };
        chain.visit(&mut visitor);

        Ok(State {
            vtmf: visitor.vtmf,
            stacks: visitor.stacks,
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
}

impl ChainVisitor for ChainParser {
    fn visit_publish_key(&mut self, _: &Chain, _: &Block, pk: &PublicKey) {
        self.vtmf.add_key(pk.clone()).unwrap();
    }

    fn visit_open_stack(&mut self, _: &Chain, _: &Block, stack: &Stack) {
        self.stacks.insert(stack.clone());
    }

    fn visit_mask_stack(&mut self, _: &Chain, _: &Block, _: Id, stack: &Stack, _: &[MaskProof]) {
        self.stacks.insert(stack.clone());
    }

    fn visit_shuffle_stack(
        &mut self,
        _: &Chain,
        _: &Block,
        _: Id,
        stack: &Stack,
        _: &ShuffleProof,
    ) {
        self.stacks.insert(stack.clone());
    }

    fn visit_shift_stack(&mut self, _: &Chain, _: &Block, _: Id, stack: &Stack, _: &ShiftProof) {
        self.stacks.insert(stack.clone());
    }

    fn visit_take_stack(&mut self, _: &Chain, _: &Block, _: Id, _: &[usize], stack: &Stack) {
        self.stacks.insert(stack.clone());
    }

    fn visit_pile_stack(&mut self, _: &Chain, _: &Block, _: &[Id], stack: &Stack) {
        self.stacks.insert(stack.clone());
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
        self.stacks
            .add_secret_share(id, block.signer(), shares.to_vec());
    }

    fn visit_unmask_stack(&mut self, _: &Chain, _: &Block, _: Id, stack: &Stack) {
        self.stacks.insert(stack.clone());
    }
}
