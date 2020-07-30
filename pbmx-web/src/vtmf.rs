use crate::keys::Fingerprint;
use wasm_bindgen::prelude::*;

use pbmx_kit::crypto::vtmf as kit;

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
impl Stack {
    pub fn id(&self) -> Fingerprint {
        Fingerprint(self.0.id())
    }
}
