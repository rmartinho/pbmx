use crate::keys::{Fingerprint, PrivateKey, PublicKey};
use wasm_bindgen::prelude::*;

use pbmx_kit::crypto::vtmf as kit;

#[wasm_bindgen]
#[repr(transparent)]
pub struct Vtmf(pub(crate) kit::Vtmf);

#[wasm_bindgen]
#[repr(transparent)]
pub struct Mask(pub(crate) kit::Mask);

#[wasm_bindgen]
#[repr(transparent)]
pub struct SecretShare(pub(crate) kit::SecretShare);

#[wasm_bindgen]
#[repr(transparent)]
pub struct Stack(pub(crate) kit::Stack);

#[wasm_bindgen]
#[repr(transparent)]
pub struct MaskProof(pub(crate) kit::MaskProof);

#[wasm_bindgen]
#[repr(transparent)]
pub struct SecretShareProof(pub(crate) kit::SecretShareProof);

#[wasm_bindgen]
#[repr(transparent)]
pub struct ShuffleProof(pub(crate) kit::ShuffleProof);

#[wasm_bindgen]
#[repr(transparent)]
pub struct RotationProof(pub(crate) kit::ShiftProof);

#[wasm_bindgen]
#[repr(transparent)]
pub struct EntanglementProof(pub(crate) kit::EntanglementProof);

#[wasm_bindgen]
impl Vtmf {
    pub fn new(sk: PrivateKey) -> Self {
        Self(kit::Vtmf::new(sk.0))
    }

    #[wasm_bindgen(js_name = privateKey)]
    pub fn private_key(&self) -> PrivateKey {
        PrivateKey(self.0.private_key())
    }

    #[wasm_bindgen(js_name = sharedKey)]
    pub fn shared_key(&self) -> PublicKey {
        PublicKey(self.0.shared_key())
    }

    #[wasm_bindgen(js_name = addKey)]
    pub fn add_key(&mut self, key: PublicKey) {
        self.0.add_key(key.0);
    }
}

#[wasm_bindgen]
impl Stack {
    pub fn id(&self) -> Fingerprint {
        Fingerprint(self.0.id())
    }
}
