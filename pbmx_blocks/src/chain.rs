//! PBMX blockchain

use crate::block::{Block, BlockBuilder, Id};
use pbmx_crypto::Error;
use pbmx_serde::{derive_base64_conversions, serialize_flat_map};
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

#[cfg(test)]
mod test {
    use super::Chain;
    use crate::block::{Block, Payload};
    use pbmx_crypto::{group::Groups, keys::Keys};
    use rand::{thread_rng, Rng};
    use std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
    };

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
        let mut chain = Chain::new();
        let mut gen = chain.build_block();
        gen.add_payload(Payload::DefineGame("test".into(), group));
        gen.add_payload(Payload::PublishKey(pk));
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
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let mut chain = Chain::new();
        let mut gen = chain.build_block();
        gen.add_payload(Payload::DefineGame("test".into(), group));
        gen.add_payload(Payload::PublishKey(pk));
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
        println!("chain = {}", original);

        let exported = original.to_string();

        let recovered = Chain::from_str(&exported).unwrap();

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
