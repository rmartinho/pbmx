//! PBMX blockchain

use crate::{
    chain::{
        block::{Block, BlockBuilder},
        payload::Payload,
        Id,
    },
    crypto::{
        keys::PublicKey,
        vtmf::{
            InsertProof, Mask, MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
            Stack,
        },
        Error,
    },
    serde::serialize_flat_map,
};
use serde::de::{Deserialize, Deserializer};
use std::collections::HashMap;

/// A blockchain
#[derive(Default, Debug, Serialize)]
pub struct Chain {
    #[serde(serialize_with = "serialize_flat_map")]
    blocks: HashMap<Id, Block>,

    #[serde(skip)]
    heads: Vec<Id>,
    #[serde(skip)]
    roots: Vec<Id>,
    #[serde(skip)]
    links: HashMap<Id, Vec<Id>>,
}

impl Chain {
    /// Creates a new empty chain
    pub fn new() -> Chain {
        Chain::default()
    }

    fn from_blocks(blocks: Vec<Block>) -> Chain {
        let mut chain = Chain::default();
        for b in blocks {
            chain.add_block(b);
        }
        chain
    }

    /// Gets the number of blocks in the chain
    pub fn count(&self) -> usize {
        self.blocks.len()
    }

    /// Visits this chain
    pub fn visit<V: ChainVisitor>(&self, v: &mut V) {
        v.visit_chain(self);
    }

    /// Gets the IDs of the heads
    pub fn heads(&self) -> &[Id] {
        &self.heads
    }

    /// Gets the IDs of the roots
    pub fn roots(&self) -> &[Id] {
        &self.roots
    }

    /// Tests whether this chain is fully merged (i.e. there is only one head)
    pub fn is_merged(&self) -> bool {
        self.heads.len() == 1
    }

    /// Tests whether this chain is fully merged (i.e. there is only one head)
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Tests whether this chain is incomplete (i.e. there are unknown blocks
    /// acknowledged)
    pub fn is_incomplete(&self) -> bool {
        !self.links.keys().all(|id| self.blocks.contains_key(id))
    }

    /// Starts building a new block that acknowledges all blocks in this chain
    pub fn build_block(&self) -> BlockBuilder {
        let mut builder = BlockBuilder::new();
        for &h in self.heads.iter() {
            builder.acknowledge(h);
        }
        builder
    }

    /// Adds a new block to this chain
    pub fn add_block(&mut self, block: Block) {
        let id = block.id();
        assert!(!self.blocks.contains_key(&id));

        for &ack in block.parent_ids().iter() {
            self.heads.retain(|&h| h != ack);
            self.links.entry(ack).or_insert_with(Vec::new).push(id);
        }
        if block.parent_ids().is_empty() {
            self.roots.push(id);
        }
        if !self.links.contains_key(&id) {
            self.heads.push(id);
        }
        self.blocks.insert(id, block);
    }

    /// An iterator over the blocks in this chain
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        Blocks::new(self)
    }
}

impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(ChainRaw::deserialize(deserializer)?.into())
    }
}

#[derive(Deserialize)]
struct ChainRaw {
    blocks: Vec<Block>,
}

impl ChainRaw {
    fn into(self) -> Chain {
        Chain::from_blocks(self.blocks)
    }
}

derive_base64_conversions!(Chain, Error);

struct Blocks<'a> {
    roots: Vec<Id>,
    chain: &'a Chain,
    incoming: HashMap<Id, usize>,
    current: Option<Id>,
}

impl<'a> Blocks<'a> {
    fn new(chain: &Chain) -> Blocks {
        Blocks {
            roots: chain.roots.clone(),
            chain: &chain,
            incoming: HashMap::new(),
            current: None,
        }
    }
}

impl<'a> Iterator for Blocks<'a> {
    type Item = &'a Block;

    fn next(&mut self) -> Option<Self::Item> {
        let blocks = &self.chain.blocks;
        loop {
            match self.current.take() {
                None => {
                    let n = self.roots.pop()?;
                    self.current = Some(n);
                    return blocks.get(&n);
                }
                Some(n) => {
                    if let Some(links) = self.chain.links.get(&n) {
                        for &m in links.iter() {
                            let entry = self.incoming.entry(m);
                            let inc =
                                entry.or_insert_with(|| blocks.get(&m).unwrap().parent_ids().len());
                            *inc -= 1;
                            if *inc == 0 {
                                self.roots.push(m);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A visitor for chains
pub trait ChainVisitor {
    /// Visits a chain
    fn visit_chain(&mut self, chain: &Chain) {
        for block in chain.blocks() {
            self.visit_block(block);
        }
    }
    /// Visits a block
    fn visit_block(&mut self, block: &Block) {
        for payload in block.payloads() {
            self.visit_payload(block, payload);
        }
    }
    /// Visits a payload
    fn visit_payload(&mut self, block: &Block, payload: &Payload) {
        use Payload::*;
        match payload {
            PublishKey(name, pk) => {
                self.visit_publish_key(block, name, pk);
            }
            OpenStack(stk) => {
                self.visit_open_stack(block, stk);
            }
            MaskStack(id, stk, proof) => {
                self.visit_mask_stack(block, *id, stk, proof);
            }
            ShuffleStack(id, stk, proof) => {
                self.visit_shuffle_stack(block, *id, stk, proof);
            }
            ShiftStack(id, stk, proof) => {
                self.visit_shift_stack(block, *id, stk, proof);
            }
            NameStack(id, name) => {
                self.visit_name_stack(block, *id, name);
            }
            TakeStack(id1, idxs, id2) => {
                self.visit_take_stack(block, *id1, idxs, *id2);
            }
            PileStacks(ids, id2) => {
                self.visit_pile_stack(block, ids, *id2);
            }
            InsertStack(id1, id2, stk, proof) => {
                self.visit_insert_stack(*id1, *id2, stk, proof);
            }
            PublishShares(id, shares, proof) => {
                self.visit_publish_shares(block, *id, shares, proof);
            }
            RandomSpec(id, spec) => {
                self.visit_random_spec(block, id, spec);
            }
            RandomEntropy(id, entropy) => {
                self.visit_random_entropy(block, id, entropy);
            }
            RandomReveal(id, share, proof) => {
                self.visit_random_reveal(block, id, share, proof);
            }
            Bytes(bytes) => {
                self.visit_bytes(block, bytes);
            }
        }
    }
    /// Visits a PublishKey payload
    fn visit_publish_key(&mut self, _block: &Block, _name: &str, _key: &PublicKey) {}
    /// Visits a OpenStack payload
    fn visit_open_stack(&mut self, _block: &Block, _stack: &Stack) {}
    /// Visits a MaskStack payload
    fn visit_mask_stack(
        &mut self,
        _block: &Block,
        _source: Id,
        _stack: &Stack,
        _proof: &[MaskProof],
    ) {
    }
    /// Visits a ShuffleStack payload
    fn visit_shuffle_stack(
        &mut self,
        _block: &Block,
        _source: Id,
        _stack: &Stack,
        _proof: &ShuffleProof,
    ) {
    }
    /// Visits a ShiftStack payload
    fn visit_shift_stack(&mut self, _block: &Block, _id: Id, _stack: &Stack, _proof: &ShiftProof) {}
    /// Visits a TakeStack payload
    fn visit_take_stack(&mut self, _block: &Block, _id1: Id, _idxs: &[usize], _id2: Id) {}
    /// Visits a PileStack payload
    fn visit_pile_stack(&mut self, _block: &Block, _ids: &[Id], _id2: Id) {}
    /// Visits a InsertToken payload
    fn visit_insert_stack(&mut self, _id1: Id, _id2: Id, _stack: &Stack, _proof: &InsertProof) {}
    /// Visits a NameStack payload
    fn visit_name_stack(&mut self, _block: &Block, _id: Id, _name: &str) {}
    /// Visits a PublishShares payload
    fn visit_publish_shares(
        &mut self,
        _block: &Block,
        _id: Id,
        _shares: &[SecretShare],
        _proof: &[SecretShareProof],
    ) {
    }
    /// Visits a RandomSpec payload
    fn visit_random_spec(&mut self, _block: &Block, _name: &str, _spec: &str) {}
    /// Visits a RandomEntropy payload
    fn visit_random_entropy(&mut self, _block: &Block, _name: &str, _entropy: &Mask) {}
    /// Visits a RandomReveal payload
    fn visit_random_reveal(
        &mut self,
        _block: &Block,
        _name: &str,
        _share: &SecretShare,
        _proof: &SecretShareProof,
    ) {
    }
    /// Visits a Bytes payload
    fn visit_bytes(&mut self, _block: &Block, _bytes: &[u8]) {}
}

#[cfg(test)]
mod test {
    use super::Chain;
    use crate::{
        chain::{block::Block, payload::Payload},
        crypto::keys::PrivateKey,
        serde::{FromBase64, ToBase64},
    };
    use rand::thread_rng;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn chain_block_iteration_works() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();
        let mut chain = Chain::new();
        let mut gen = chain.build_block();
        gen.add_payload(Payload::PublishKey("foo".into(), pk));
        chain.add_block(gen.build(&sk));
        let gid = chain.roots[0];
        let mut b0 = chain.build_block();
        b0.add_payload(Payload::Bytes(vec![0, 1, 2, 3, 4]));
        b0.add_payload(Payload::Bytes(vec![5, 6, 7, 8, 9]));
        let b0 = b0.build(&sk);

        let mut b1 = chain.build_block();
        b1.add_payload(Payload::Bytes(vec![9, 8, 7, 6, 5]));
        let b1 = b1.build(&sk);

        chain.add_block(b0.clone());
        chain.add_block(b1.clone());

        let mut b2 = chain.build_block();
        b2.add_payload(Payload::Bytes(vec![4, 3, 2, 1, 0]));
        let b2 = b2.build(&sk);
        chain.add_block(b2.clone());

        let blocks: Vec<_> = chain.blocks().map(|b| b.id()).collect();
        assert_eq!(blocks, vec![gid, b1.id(), b0.id(), b2.id()])
    }

    #[test]
    fn chain_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();
        let mut chain = Chain::new();
        let mut gen = chain.build_block();
        gen.add_payload(Payload::PublishKey("foo".into(), pk));
        chain.add_block(gen.build(&sk));
        let mut b0 = chain.build_block();
        b0.add_payload(Payload::Bytes(vec![0, 1, 2, 3, 4]));
        b0.add_payload(Payload::Bytes(vec![5, 6, 7, 8, 9]));
        let b0 = b0.build(&sk);

        let mut b1 = chain.build_block();
        b1.add_payload(Payload::Bytes(vec![9, 8, 7, 6, 5]));
        let b1 = b1.build(&sk);

        chain.add_block(b0.clone());
        chain.add_block(b1.clone());

        let mut b2 = chain.build_block();
        b2.add_payload(Payload::Bytes(vec![4, 3, 2, 1, 0]));
        let b2 = b2.build(&sk);
        chain.add_block(b2.clone());
        let original = chain;

        let exported = original.to_base64().unwrap();
        dbg!(&exported);

        let recovered = Chain::from_base64(&exported).unwrap();

        assert_eq!(original.heads, recovered.heads);
        assert_eq!(original.roots, recovered.roots);
        let original_ids: BTreeSet<_> = original.blocks.values().map(Block::id).collect();
        let recovered_ids: BTreeSet<_> = recovered.blocks.values().map(Block::id).collect();
        assert_eq!(original_ids, recovered_ids);
        let original_links: BTreeMap<_, BTreeSet<_>> = original
            .links
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        let recovered_links: BTreeMap<_, BTreeSet<_>> = recovered
            .links
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        assert_eq!(original_links, recovered_links);
    }
}