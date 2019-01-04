//! PBMX blockchain

use crate::block::{Block, BlockBuilder, Id, Payload};
use pbmx_crypto::{derive_base64_conversions, keys::PrivateKey, serde::serialize_flat_map};
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
    /// Creates a new chain with a genesis block describing a game
    pub fn new(desc: String, sk: &PrivateKey) -> Chain {
        let mut builder = BlockBuilder::new();
        builder
            .add_payload(Payload::DefineGame(desc))
            .add_payload(Payload::PublishGroup(sk.group().clone()))
            .add_payload(Payload::PublishKey(sk.public_key()));
        let genesis = builder.build(sk);

        Chain::from_blocks(vec![genesis])
    }

    fn from_blocks(blocks: Vec<Block>) -> Chain {
        let mut chain = Chain::default();
        for b in blocks {
            chain.add_block(b);
        }
        chain
    }

    /// Tests whether this chain is fully merged (i.e. there is only one head)
    pub fn is_merged(&self) -> bool {
        self.heads.len() == 1
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

        for &ack in block.acks.iter() {
            self.heads.retain(|&h| h != ack);
            self.links.entry(ack).or_insert_with(Vec::new).push(id);
        }
        if block.acks.is_empty() {
            self.roots.push(id);
        }
        if !self.links.contains_key(&id) {
            self.heads.push(id);
        }
        self.blocks.insert(id, block);
    }

    /// An iterator over the blocks in this chain
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        BlockIter::new(self)
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

derive_base64_conversions!(Chain);

struct BlockIter<'a> {
    roots: Vec<Id>,
    chain: &'a Chain,
    incoming: HashMap<Id, usize>,
    current: Option<Id>,
}

impl<'a> BlockIter<'a> {
    fn new(chain: &Chain) -> BlockIter {
        BlockIter {
            roots: chain.roots.clone(),
            chain: &chain,
            incoming: HashMap::new(),
            current: None,
        }
    }
}

impl<'a> Iterator for BlockIter<'a> {
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
                            let inc = entry.or_insert_with(|| blocks.get(&m).unwrap().acks.len());
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

#[cfg(test)]
mod test {
    use super::Chain;
    use crate::block::Payload;
    use pbmx_crypto::{group::Groups, keys::Keys};
    use rand::{thread_rng, Rng};

    #[test]
    fn chain_block_iteration_works() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let mut chain = Chain::new("test".into(), &sk);
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
}
