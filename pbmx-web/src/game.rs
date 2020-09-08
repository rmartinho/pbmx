use crate::{
    chain::{Block, BlockBuilder, Payload},
    keys::{Fingerprint, PrivateKey, PublicKey},
    vtmf::{Mask, SecretShare, SecretShareProof},
};
use js_sys::{Array, Map};
use wasm_bindgen::prelude::*;

pub use pbmx_kit::state as kit;

#[wasm_bindgen]
#[repr(transparent)]
pub struct Game(pub(crate) kit::State);

#[wasm_bindgen]
#[repr(transparent)]
pub struct Rng(pub(crate) kit::Rng);

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
    pub fn add_block(&mut self, block: Block) -> Option<Block> {
        self.0.add_block(&block.0).ok()?;
        Some(block)
    }

    #[wasm_bindgen(js_name = finishBlock)]
    pub fn finish_block(&mut self, builder: BlockBuilder) -> Option<Block> {
        let block = builder.0.build(&self.0.vtmf.private_key());
        self.0.add_block(&block).ok()?;
        Some(Block(block))
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

    pub fn rngs(&self) -> Map {
        let mut map = Map::new();
        for (n, r) in self.0.rngs.iter() {
            map = map.set(&n.into(), &Rng(r.clone()).into());
        }
        map
    }

    #[wasm_bindgen(js_name = maskRandom)]
    pub fn mask_random(&self) -> Mask {
        Mask(self.0.vtmf.mask_random(&mut pbmx_kit::random::thread_rng()))
    }

    #[wasm_bindgen(js_name = unmaskShare)]
    pub fn unmask_share(&self, mask: &Mask) -> Array {
        let array = Array::new();
        let (share, proof) = self.0.vtmf.unmask_share(&mask.0);
        array.push(&SecretShare(share).into());
        array.push(&SecretShareProof(proof).into());
        array
    }
}

#[wasm_bindgen]
impl Rng {
    pub fn spec(&self) -> String {
        self.0.spec()
    }

    pub fn mask(&self) -> Mask {
        Mask(*self.0.mask())
    }

    #[wasm_bindgen(js_name = addEntropy)]
    pub fn add_entropy(&mut self, party: &Fingerprint, mask: &Mask) {
        self.0.add_entropy(party.0, &mask.0);
    }

    #[wasm_bindgen(js_name = isGenerated)]
    pub fn is_generated(&self) -> bool {
        self.0.is_generated()
    }

    #[wasm_bindgen(js_name = isRevealed)]
    pub fn is_revealed(&self) -> bool {
        self.0.is_revealed()
    }

    pub fn state(&self, game: &Game) -> String {
        let fp = game.player_fingerprint().0;
        if !self.0.is_generated() {
            if self.0.entropy_parties().contains(&fp) {
                "waitEntropy"
            } else {
                "entropy"
            }
        } else if !self.0.is_revealed() {
            if self.0.secret_parties().contains(&fp) {
                "waitReveal"
            } else {
                "reveal"
            }
        } else {
            "revealed"
        }
        .into()
    }

    pub fn value(&self, game: &Game) -> u64 {
        self.0.gen(&game.0.vtmf)
    }
}
