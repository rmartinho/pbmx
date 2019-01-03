//! PBMX blockchain

use crate::block::{Block, BlockBuilder, Id, Payload};
use pbmx_crypto::{keys::PrivateKey, serde::serialize_flat_map};
use std::collections::HashMap;

/// A blockchain
#[derive(Serialize)]
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
        let genesis_id = genesis.id();
        let mut blocks = HashMap::new();
        blocks.insert(genesis_id, genesis);
        let heads = vec![genesis_id];

        Chain {
            blocks,
            roots: heads.clone(),
            heads,
            links: HashMap::new(),
        }
    }

    /// Tests whether this chain is fully merged (i.e. there is only one head)
    pub fn is_merged(&self) -> bool {
        self.heads.len() == 1
    }

    /// Starts building a new block that acknowledges all blocks in this chain
    pub fn build_new(&self) -> BlockBuilder {
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
        self.blocks.insert(id, block);
        self.heads.push(id);
    }
}
