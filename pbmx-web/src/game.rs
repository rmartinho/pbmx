use crate::{
    chain::{Block, BlockBuilder, Payload},
    keys::{Fingerprint, PrivateKey, PublicKey},
};
use js_sys::{Array, Map};
use wasm_bindgen::prelude::*;

pub use pbmx_kit::state as kit;

#[wasm_bindgen]
#[repr(transparent)]
pub struct Game(pub(crate) kit::State);

#[wasm_bindgen]
impl Game {
    pub fn new(sk: PrivateKey) -> Self {
        Self(kit::State::new(sk.0))
    }

    #[wasm_bindgen(js_name = blockCount)]
    pub fn block_count(&self) -> usize {
        self.0.chain.count()
    }

    pub fn blocks(&self) -> Array {
        let array = Array::new();
        for b in self.0.chain.blocks().cloned() {
            array.push(&Block(b).into());
        }
        array
    }

    pub fn payloads(&self) -> Array {
        let array = Array::new();
        for b in self.0.chain.blocks() {
            for p in b.payloads().cloned() {
                array.push(&Payload(p).into());
            }
        }
        array
    }

    #[wasm_bindgen(js_name = playerCount)]
    pub fn player_count(&self) -> usize {
        self.0.names.len()
    }

    pub fn players(&self) -> Map {
        let mut map = Map::new();
        for (fp, n) in self.0.names.iter() {
            map = map.set(&Fingerprint(*fp).export().into(), &n.into());
        }
        map
    }

    pub fn joined(&self) -> bool {
        self.0.names.contains_key(&self.player_fingerprint().0)
    }

    #[wasm_bindgen(js_name = buildBlock)]
    pub fn build_block(&self) -> BlockBuilder {
        BlockBuilder(self.0.chain.build_block())
    }

    #[wasm_bindgen(js_name = addBlock)]
    pub fn add_block(&mut self, block: Block) -> Block {
        self.0.add_block(&block.0).unwrap();
        block
    }

    #[wasm_bindgen(js_name = finishBlock)]
    pub fn finish_block(&mut self, builder: BlockBuilder) -> Block {
        let block = builder.0.build(&self.0.vtmf.private_key());
        self.0.add_block(&block).unwrap();
        Block(block)
    }

    pub fn join(&mut self, name: String) -> BlockBuilder {
        let pk = PublicKey(self.0.vtmf.public_key());
        let mut builder = self.build_block();
        builder.add_payload(Payload::publish_key(name, pk));
        builder
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(self.0.vtmf.shared_key().fingerprint())
    }

    #[wasm_bindgen(js_name = playerFingerprint)]
    pub fn player_fingerprint(&self) -> Fingerprint {
        Fingerprint(self.0.vtmf.public_key().fingerprint())
    }
}
