use crate::{
    keys::{Fingerprint, PrivateKey, PublicKey},
    utils,
    vtmf::{
        EntanglementProof, Mask, MaskProof, RotationProof, SecretShare, SecretShareProof,
        ShuffleProof, Stack,
    },
};
use wasm_bindgen::prelude::*;

use pbmx_kit::chain as kit;

#[wasm_bindgen]
#[repr(transparent)]
pub struct Chain(pub(crate) kit::Chain);

#[wasm_bindgen]
#[repr(transparent)]
pub struct Block(pub(crate) kit::Block);

#[wasm_bindgen]
#[repr(transparent)]
pub struct BlockBuilder(pub(crate) kit::BlockBuilder);

#[wasm_bindgen]
#[repr(transparent)]
pub struct Payload(pub(crate) kit::Payload);

#[wasm_bindgen]
impl Chain {
    pub fn new() -> Chain {
        Self(kit::Chain::new())
    }

    pub fn count(&self) -> usize {
        self.0.count()
    }

    #[wasm_bindgen(js_name = buildBlock)]
    pub fn build_block(&self) -> BlockBuilder {
        BlockBuilder(self.0.build_block())
    }

    #[wasm_bindgen(js_name = addBlock)]
    pub fn add_block(&mut self, block: Block) {
        self.0.add_block(block.0);
    }
}

#[wasm_bindgen]
impl Block {
    pub fn id(&self) -> Fingerprint {
        Fingerprint(self.0.id())
    }

    pub fn signer(&self) -> Fingerprint {
        Fingerprint(self.0.signer())
    }

    // is_valid

    #[wasm_bindgen(js_name = parentIds)]
    pub fn parent_ids(&self) -> Vec<u32> {
        let it = self.0.parent_ids().iter().map(|id| Fingerprint(*id));
        utils::vec_to_wasm(it)
    }

    // payloads

    // visit

    pub fn export(&self) -> String {
        use pbmx_kit::serde::ToBytes;
        base64::encode_config(self.0.to_bytes().unwrap(), base64::URL_SAFE_NO_PAD)
    }

    pub fn import(s: &str) -> Result<Block, JsValue> {
        use pbmx_kit::serde::FromBytes;
        let e = "invalid block";
        Ok(Self(
            kit::Block::from_bytes(
                &base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err(|_| e)?,
            )
            .map_err(|_| e)?,
        ))
    }
}

#[wasm_bindgen]
impl BlockBuilder {
    #[wasm_bindgen(js_name = addPayload)]
    pub fn add_payload(&mut self, payload: Payload) {
        self.0.add_payload(payload.0);
    }

    pub fn build(self, sk: &PrivateKey) -> Block {
        Block(self.0.build(&sk.0))
    }
}

#[wasm_bindgen]
impl Payload {
    pub fn id(&self) -> Fingerprint {
        Fingerprint(self.0.id())
    }

    #[wasm_bindgen(js_name = publishKey)]
    pub fn publish_key(name: String, pk: PublicKey) -> Payload {
        Payload(kit::Payload::PublishKey(name, pk.0))
    }

    #[wasm_bindgen(js_name = openStack)]
    pub fn open_stack(stk: Stack) -> Payload {
        Payload(kit::Payload::OpenStack(stk.0))
    }

    #[wasm_bindgen(js_name = maskStack)]
    pub fn mask_stack(id: Fingerprint, stk: Stack, proofs: &[u32]) -> Payload {
        let proofs = utils::vec_from_wasm(proofs)
            .map(|p: MaskProof| p.0)
            .collect();
        Payload(kit::Payload::MaskStack(id.0, stk.0, proofs))
    }

    #[wasm_bindgen(js_name = shuffleStack)]
    pub fn shuffle_stack(id: Fingerprint, stk: Stack, proof: ShuffleProof) -> Payload {
        Payload(kit::Payload::ShuffleStack(id.0, stk.0, proof.0))
    }

    #[wasm_bindgen(js_name = rotateStack)]
    pub fn rotate_stack(id: Fingerprint, stk: Stack, proof: RotationProof) -> Payload {
        Payload(kit::Payload::ShiftStack(id.0, stk.0, proof.0))
    }

    #[wasm_bindgen(js_name = nameStack)]
    pub fn name_stack(id: Fingerprint, name: String) -> Payload {
        Payload(kit::Payload::NameStack(id.0, name))
    }

    #[wasm_bindgen(js_name = takeStack)]
    pub fn take_stack(id1: Fingerprint, indices: Vec<usize>, id2: Fingerprint) -> Payload {
        Payload(kit::Payload::TakeStack(id1.0, indices, id2.0))
    }

    #[wasm_bindgen(js_name = pileStacks)]
    pub fn pile_stacks(ids: &[u32], id: Fingerprint) -> Payload {
        let ids = utils::vec_from_wasm(ids)
            .map(|f: Fingerprint| f.0)
            .collect();
        Payload(kit::Payload::PileStacks(ids, id.0))
    }

    #[wasm_bindgen(js_name = publishShares)]
    pub fn publish_shares(id: Fingerprint, shares: &[u32], proofs: &[u32]) -> Payload {
        let shares = utils::vec_from_wasm(shares)
            .map(|s: SecretShare| s.0)
            .collect();
        let proofs = utils::vec_from_wasm(proofs)
            .map(|p: SecretShareProof| p.0)
            .collect();
        Payload(kit::Payload::PublishShares(id.0, shares, proofs))
    }

    #[wasm_bindgen(js_name = randomSpec)]
    pub fn random_spec(name: String, spec: String) -> Payload {
        Payload(kit::Payload::RandomSpec(name, spec))
    }

    #[wasm_bindgen(js_name = randomEntropy)]
    pub fn random_entropy(name: String, entropy: Mask) -> Payload {
        Payload(kit::Payload::RandomEntropy(name, entropy.0))
    }

    #[wasm_bindgen(js_name = randomReveal)]
    pub fn random_reveal(name: String, share: SecretShare, proof: SecretShareProof) -> Payload {
        Payload(kit::Payload::RandomReveal(name, share.0, proof.0))
    }

    #[wasm_bindgen(js_name = proveEntanglement)]
    pub fn prove_entanglement(ids1: &[u32], ids2: &[u32], proof: EntanglementProof) -> Payload {
        let ids1 = utils::vec_from_wasm(ids1)
            .map(|f: Fingerprint| f.0)
            .collect();
        let ids2 = utils::vec_from_wasm(ids2)
            .map(|f: Fingerprint| f.0)
            .collect();
        Payload(kit::Payload::ProveEntanglement(ids1, ids2, proof.0))
    }

    pub fn text(s: String) -> Payload {
        Payload(kit::Payload::Text(s))
    }

    pub fn bytes(b: Vec<u8>) -> Payload {
        Payload(kit::Payload::Bytes(b))
    }
}
