use crate::{
    constants::{
        BLOCKS_FOLDER_NAME, BLOCK_EXTENSION, CURRENT_BLOCK_FILE_NAME, KEY_FILE_NAME,
        SECRETS_FOLDER_NAME,
    },
    random::Rng,
    stack_map::StackMap,
    Error, Result,
};
use pbmx_chain::{
    block::Block,
    chain::{Chain, ChainVisitor},
    payload::Payload,
    Id,
};
use pbmx_curve::{
    keys::{PrivateKey, PublicKey},
    map,
    vtmf::{
        InsertProof, Mask, MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
        Stack, Vtmf,
    },
};
use pbmx_serde::{FromBase64, ToBase64};
use std::{collections::HashMap, ffi::OsStr, fs, path::PathBuf};

#[derive(Debug)]
pub struct State {
    pub vtmf: Vtmf,
    pub chain: Chain,
    pub stacks: StackMap,
    pub rngs: HashMap<String, Rng>,
    pub payloads: Vec<Payload>,
}

impl State {
    pub fn read(include_temp: bool) -> Result<State> {
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

        if include_temp {
            let mut builder = chain.build_block();
            for p in payloads.iter().cloned() {
                builder.add_payload(p);
            }
            let block = builder.build(&sk);
            chain.add_block(block);
        }

        let mut visitor = ChainParser {
            vtmf: Vtmf::new(sk),
            stacks: StackMap::new(),
            rngs: HashMap::new(),
            valid: true,
        };
        chain.visit(&mut visitor);

        if visitor.valid {
            Ok(State {
                vtmf: visitor.vtmf,
                stacks: visitor.stacks,
                rngs: visitor.rngs,
                chain,
                payloads,
            })
        } else {
            Err(Error::InvalidBlock)
        }
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
    rngs: HashMap<String, Rng>,
    valid: bool,
}

impl ChainVisitor for ChainParser {
    fn visit_block(&mut self, block: &Block) {
        for payload in block.payloads() {
            self.visit_payload(block, payload);
            if !self.valid {
                break;
            }
        }
    }

    fn visit_publish_key(&mut self, block: &Block, pk: &PublicKey) {
        self.valid = self.valid && block.signer() == pk.fingerprint();

        if self.valid {
            self.vtmf.add_key(pk.clone()).unwrap();
        }
    }

    fn visit_open_stack(&mut self, _: &Block, stack: &Stack) {
        self.valid = self.valid
            && stack
                .iter()
                .all(|m| map::from_curve(&self.vtmf.unmask_open(m)).is_some());

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_mask_stack(&mut self, _: &Block, id: Id, stack: &Stack, proof: &[MaskProof]) {
        self.valid = self.valid
            && self
                .stacks
                .get_by_id(&id)
                .map(|src| {
                    src.iter()
                        .zip(stack.iter())
                        .zip(proof.iter())
                        .all(|((a, b), proof)| self.vtmf.verify_remask(a, b, proof).is_ok())
                })
                .unwrap_or(false);

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_shuffle_stack(&mut self, _: &Block, id: Id, stack: &Stack, proof: &ShuffleProof) {
        self.valid = self.valid
            && self
                .stacks
                .get_by_id(&id)
                .map(|src| self.vtmf.verify_mask_shuffle(src, stack, proof).is_ok())
                .unwrap_or(false);

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_shift_stack(&mut self, _: &Block, id: Id, stack: &Stack, proof: &ShiftProof) {
        self.valid = self.valid
            && self
                .stacks
                .get_by_id(&id)
                .map(|src| self.vtmf.verify_mask_shift(src, stack, proof).is_ok())
                .unwrap_or(false);

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_take_stack(&mut self, _: &Block, id: Id, indices: &[usize], stack: &Stack) {
        self.valid = self.valid
            && self
                .stacks
                .get_by_id(&id)
                .map(|src| indices.iter().zip(stack.iter()).all(|(i, x)| src[*i] == *x))
                .unwrap_or(false);

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_pile_stack(&mut self, _: &Block, ids: &[Id], stack: &Stack) {
        let mut srcs = ids.iter().map(|id| self.stacks.get_by_id(&id));
        self.valid = self.valid
            && srcs.all(|x| x.is_some())
            && srcs
                .map(Option::unwrap)
                .flat_map(|stk| stk.iter())
                .zip(stack.iter())
                .all(|(a, b)| *a == *b);

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_insert_stack(&mut self, id1: Id, id2: Id, stack: &Stack, proof: &InsertProof) {
        self.valid = self.valid
            && self
                .stacks
                .get_by_id(&id1)
                .and_then(|s1| self.stacks.get_by_id(&id2).map(|s2| (s1, s2)))
                .map(|(s1, s2)| self.vtmf.verify_mask_insert(s1, s2, stack, proof).is_ok())
                .unwrap_or(false);

        if self.valid {
            self.stacks.insert(stack.clone());
        }
    }

    fn visit_name_stack(&mut self, _: &Block, id: Id, name: &str) {
        self.valid = self.valid && self.stacks.get_by_id(&id).is_some();

        if self.valid {
            self.stacks.set_name(id, name.to_string());
        }
    }

    fn visit_publish_shares(
        &mut self,
        block: &Block,
        id: Id,
        shares: &[SecretShare],
        proofs: &[SecretShareProof],
    ) {
        self.valid = self.valid
            && self
                .stacks
                .get_by_id(&id)
                .map(|src| {
                    src.iter()
                        .zip(shares.iter())
                        .zip(proofs.iter())
                        .all(|((m, s), p)| {
                            self.vtmf.verify_unmask(m, &block.signer(), s, p).is_ok()
                        })
                })
                .unwrap_or(false);

        if self.valid {
            self.stacks
                .add_secret_share(id, block.signer(), shares.to_vec());
        }
    }

    fn visit_random_bound(&mut self, _: &Block, name: &str, bound: u64) {
        let e = self.rngs.get(name);
        self.valid = self.valid && e.map(|rng| rng.bound() == bound).unwrap_or(true);

        if self.valid && e.is_none() {
            self.rngs
                .insert(name.into(), Rng::new(self.vtmf.parties(), bound));
        }
    }

    fn visit_random_entropy(&mut self, block: &Block, name: &str, entropy: &Mask) {
        let fp = block.signer();
        let e = self.rngs.get_mut(name);
        self.valid = self.valid
            && e.as_ref()
                .map(|rng| !rng.is_generated() && !rng.entropy_parties().contains(&fp))
                .unwrap_or(false);

        if self.valid {
            e.unwrap().add_entropy(fp, entropy);
        }
    }

    fn visit_random_reveal(
        &mut self,
        block: &Block,
        name: &str,
        share: &SecretShare,
        proof: &SecretShareProof,
    ) {
        let fp = block.signer();
        let vtmf = &self.vtmf;
        let e = self.rngs.get_mut(name);
        self.valid = self.valid
            && e.as_ref()
                .map(|rng| {
                    !rng.is_revealed()
                        && !rng.secret_parties().contains(&fp)
                        && vtmf.verify_unmask(rng.mask(), &fp, share, proof).is_ok()
                })
                .unwrap_or(false);

        if self.valid {
            e.unwrap().add_secret(fp, share);
        }
    }
}
