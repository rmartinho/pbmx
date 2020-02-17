//! PBMX state

use crate::{
    chain::{Block, BlockVisitor, Chain, Id, PayloadVisitor},
    crypto::{
        keys::{Fingerprint, PrivateKey, PublicKey},
        vtmf::{
            DisjointProof, EntanglementProof, Mask, MaskProof, SecretShare, SecretShareProof,
            ShiftProof, ShuffleProof, Stack, SubsetProof, SupersetProof, Vtmf,
        },
    },
};
use std::collections::HashMap;

mod stack_map;
pub use stack_map::{PrivateSecretMap, SecretMap, StackMap};

mod rng;
pub use rng::Rng;

mod claim;
pub use claim::Claim;

type PlayerMap = HashMap<Fingerprint, String>;
type RngMap = HashMap<String, Rng>;
type ClaimMap = HashMap<Id, Claim>;

/// The end state of a chain
#[derive(Debug)]
pub struct State {
    /// The VTMF instance
    pub vtmf: Vtmf,
    /// The chain
    pub chain: Chain,
    /// The player names
    pub names: PlayerMap,
    /// The stacks
    pub stacks: StackMap,
    /// The RNGs
    pub rngs: RngMap,
    /// The claims
    pub claims: ClaimMap,
}

impl State {
    /// Creates a new blank state with a given private key
    pub fn new(sk: PrivateKey) -> Self {
        Self {
            vtmf: Vtmf::new(sk),
            names: PlayerMap::new(),
            chain: Chain::new(),
            stacks: StackMap::new(),
            rngs: RngMap::new(),
            claims: ClaimMap::new(),
        }
    }

    /// Adds a block's payloads to this state
    pub fn add_block(&mut self, b: &Block) -> Result<(), ()> {
        let mut adder = BlockAdder {
            state: self,
            valid: true,
        };
        b.visit(&mut adder);
        if adder.valid {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Adds a stack's private secrets to this state
    pub fn add_secrets<It>(&mut self, it: It) -> Result<(), ()>
    where
        It: Iterator<Item = (Mask, Mask)>,
    {
        self.stacks.add_private_secrets(it)
    }
}

struct BlockAdder<'a> {
    state: &'a mut State,
    valid: bool,
}

impl<'a> BlockVisitor for BlockAdder<'a> {
    fn visit_block(&mut self, block: &Block) {
        for payload in block.payloads() {
            self.visit_payload(block, payload);
            if !self.valid {
                return;
            }
            if payload.is_claim() {
                let claim = Claim::new(payload.clone());
                self.state.claims.insert(claim.id(), claim);
            }
            for claim in self.state.claims.values_mut() {
                if claim.needs_share(payload) {
                    claim.add_share(block.signer(), payload.clone());
                }
                claim.verify(&self.state.vtmf, &self.state.stacks);
            }
        }
        if self.valid {
            self.state.chain.add_block(block.clone());
        }
    }
}

impl<'a> PayloadVisitor for BlockAdder<'a> {
    fn visit_publish_key(&mut self, block: &Block, name: &str, key: &PublicKey) {
        self.valid = self.valid && block.signer() == key.fingerprint();

        if self.valid {
            self.state.vtmf.add_key(key.clone());
            self.state.names.insert(key.fingerprint(), name.to_string());
        }
    }

    fn visit_open_stack(&mut self, _: &Block, stack: &Stack) {
        self.valid = self.valid && stack.iter().all(Mask::is_open);

        if self.valid {
            self.state.stacks.insert(stack.clone());
        }
    }

    fn visit_hidden_stack(&mut self, _: &Block, stack: &Stack) {
        if self.valid {
            self.state.stacks.insert(stack.clone());
        }
    }

    fn visit_mask_stack(&mut self, _: &Block, source: Id, stack: &Stack, proofs: &[MaskProof]) {
        self.valid = self.valid
            && self
                .state
                .stacks
                .get_by_id(&source)
                .map(|src| {
                    src.iter()
                        .zip(stack.iter())
                        .zip(proofs.iter())
                        .all(|((a, b), p)| self.state.vtmf.verify_remask(a, b, p).is_ok())
                })
                .unwrap_or(false);

        if self.valid {
            self.state.stacks.insert(stack.clone());
        }
    }

    fn visit_shuffle_stack(&mut self, _: &Block, source: Id, stack: &Stack, proof: &ShuffleProof) {
        self.valid = self.valid
            && self
                .state
                .stacks
                .get_by_id(&source)
                .map(|src| {
                    self.state
                        .vtmf
                        .verify_mask_shuffle(src, stack, proof)
                        .is_ok()
                })
                .unwrap_or(false);

        if self.valid {
            self.state.stacks.insert(stack.clone());
        }
    }

    fn visit_shift_stack(&mut self, _: &Block, source: Id, stack: &Stack, proof: &ShiftProof) {
        self.valid = self.valid
            && self
                .state
                .stacks
                .get_by_id(&source)
                .map(|src| self.state.vtmf.verify_mask_shift(src, stack, proof).is_ok())
                .unwrap_or(false);

        if self.valid {
            self.state.stacks.insert(stack.clone());
        }
    }

    fn visit_take_stack(&mut self, _: &Block, source: Id, indices: &[usize], target: Id) {
        let src = self.state.stacks.get_by_id(&source);
        self.valid = self.valid
            && src
                .map(|src| indices.iter().all(|i| *i < src.len()))
                .unwrap_or(false);

        if !self.valid {
            return;
        }

        let src = src.unwrap();
        let stack: Stack = indices.iter().map(|i| src[*i]).collect();
        self.valid = self.valid && stack.id() == target;

        if self.valid {
            self.state.stacks.insert(stack);
        }
    }

    fn visit_pile_stack(&mut self, _: &Block, sources: &[Id], target: Id) {
        let stacks = &self.state.stacks;
        let mut srcs = sources.iter().map(|id| stacks.get_by_id(&id));
        self.valid = self.valid && srcs.all(|s| s.is_some());

        if !self.valid {
            return;
        }

        let stack: Stack = srcs
            .map(Option::unwrap)
            .flat_map(|stk| stk.iter())
            .cloned()
            .collect();

        self.valid = self.valid && stack.id() == target;

        if self.valid {
            self.state.stacks.insert(stack.clone());
        }
    }

    fn visit_name_stack(&mut self, _: &Block, id: Id, name: &str) {
        self.valid = self.valid && self.state.stacks.get_by_id(&id).is_some();

        if self.valid {
            self.state.stacks.set_name(id, name.to_string());
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
                .state
                .stacks
                .get_by_id(&id)
                .map(|src| {
                    src.iter()
                        .zip(shares.iter())
                        .zip(proofs.iter())
                        .all(|((m, s), p)| {
                            self.state
                                .vtmf
                                .verify_unmask(m, &block.signer(), s, p)
                                .is_ok()
                        })
                })
                .unwrap_or(false);

        if self.valid {
            self.state
                .stacks
                .add_secret_share(id, block.signer(), shares.to_vec());
        }
    }

    fn visit_random_spec(&mut self, _: &Block, name: &str, spec: &str) {
        let e = self.state.rngs.get(name);
        self.valid = self.valid && e.map(|rng| rng.spec() == spec).unwrap_or(true);

        if self.valid && e.is_none() {
            let rng = Rng::new(self.state.vtmf.parties(), spec);
            self.valid = self.valid && rng.is_ok();
            self.state.rngs.insert(name.into(), rng.unwrap());
        }
    }

    fn visit_random_entropy(&mut self, block: &Block, name: &str, entropy: &Mask) {
        let fp = block.signer();
        let e = self.state.rngs.get_mut(name);
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
        let vtmf = &self.state.vtmf;
        let e = self.state.rngs.get_mut(name);
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

    fn visit_prove_entanglement(
        &mut self,
        _block: &Block,
        source_ids: &[Id],
        shuffle_ids: &[Id],
        proof: &EntanglementProof,
    ) {
        let stacks = &self.state.stacks;
        let sources: Vec<_> = source_ids.iter().map(|id| stacks.get_by_id(id)).collect();
        let shuffles: Vec<_> = shuffle_ids.iter().map(|id| stacks.get_by_id(id)).collect();

        self.valid = self.valid
            && sources.iter().all(Option::is_some)
            && shuffles.iter().all(Option::is_some);

        if !self.valid {
            return;
        }

        let sources = sources.iter().map(|s| s.unwrap());
        let shuffles = shuffles.iter().map(|s| s.unwrap());

        self.valid = self.valid
            && self
                .state
                .vtmf
                .verify_entanglement(sources, shuffles, proof)
                .is_ok();
    }

    fn visit_prove_subset(&mut self, _block: &Block, sub_id: Id, sup_id: Id, proof: &SubsetProof) {
        let stacks = &self.state.stacks;
        let sub = stacks.get_by_id(&sub_id);
        let sup = stacks.get_by_id(&sup_id);

        self.valid = self.valid && sub.is_some() && sup.is_some();
        if !self.valid {
            return;
        }
        let sub = sub.unwrap();
        let sup = sup.unwrap();

        self.valid = self.valid && self.state.vtmf.verify_subset(sub, sup, proof).is_ok();

        if self.valid {
            self.state.stacks.insert(proof.shuffle[..].into());
        }
    }

    fn visit_prove_superset(
        &mut self,
        _block: &Block,
        sup_id: Id,
        sub_id: Id,
        proof: &SupersetProof,
    ) {
        let stacks = &self.state.stacks;
        let sup = stacks.get_by_id(&sup_id);
        let sub = stacks.get_by_id(&sub_id);

        self.valid = self.valid && sup.is_some() && sub.is_some();

        if !self.valid {
            return;
        }
        let sup = sup.unwrap();
        let sub = sub.unwrap();

        self.valid = self.valid && self.state.vtmf.verify_superset(sup, sub, proof).is_ok();

        if self.valid {
            self.state.stacks.insert(proof.shuffle[..proof.n].into());
        }
    }

    fn visit_prove_disjoint(
        &mut self,
        _block: &Block,
        id1: Id,
        id2: Id,
        sup_id: Id,
        proof: &DisjointProof,
    ) {
        let stacks = &self.state.stacks;
        let s1 = stacks.get_by_id(&id1);
        let s2 = stacks.get_by_id(&id2);
        let sup = stacks.get_by_id(&sup_id);

        self.valid = self.valid && s1.is_some() && s2.is_some() && sup.is_some();

        if !self.valid {
            return;
        }
        let s1 = s1.unwrap();
        let s2 = s2.unwrap();
        let sup = sup.unwrap();

        self.valid = self.valid && self.state.vtmf.verify_disjoint(s1, s2, sup, proof).is_ok();

        if self.valid {
            self.state.stacks.insert(proof.shuffle[..].into());
        }
    }
}
