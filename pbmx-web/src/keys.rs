use pbmx_kit::random::thread_rng;
use wasm_bindgen::prelude::*;

use pbmx_kit::crypto::keys as kit;

#[wasm_bindgen]
#[repr(transparent)]
pub struct PrivateKey(pub(crate) kit::PrivateKey);

#[wasm_bindgen]
#[repr(transparent)]
pub struct PublicKey(pub(crate) kit::PublicKey);

#[wasm_bindgen]
#[repr(transparent)]
pub struct Fingerprint(pub(crate) kit::Fingerprint);

#[wasm_bindgen]
impl PrivateKey {
    pub fn random() -> Self {
        let mut rng = thread_rng();
        Self(kit::PrivateKey::random(&mut rng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    pub fn export(&self) -> String {
        use pbmx_kit::serde::ToBytes;
        base64::encode_config(self.0.to_bytes().unwrap(), base64::URL_SAFE_NO_PAD)
    }

    pub fn import(s: &str) -> Result<PrivateKey, JsValue> {
        use pbmx_kit::serde::FromBytes;
        let e = "invalid private key";
        Ok(Self(
            kit::PrivateKey::from_bytes(
                &base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err(|_| e)?,
            )
            .map_err(|_| e)?,
        ))
    }
}

#[wasm_bindgen]
impl PublicKey {
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(self.0.fingerprint())
    }

    pub fn export(&self) -> String {
        use pbmx_kit::serde::ToBytes;
        base64::encode_config(self.0.to_bytes().unwrap(), base64::URL_SAFE_NO_PAD)
    }

    pub fn import(s: &str) -> Result<PublicKey, JsValue> {
        use pbmx_kit::serde::FromBytes;
        Ok(Self(
            kit::PublicKey::from_bytes(
                &base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err(|_| "invalid base64")?,
            )
            .map_err(|_| "invalid public key")?,
        ))
    }
}

#[wasm_bindgen]
impl Fingerprint {
    pub fn export(&self) -> String {
        format!("{}", self.0)
    }

    pub fn import(s: &str) -> Result<Fingerprint, JsValue> {
        use std::str::FromStr;
        let e = "invalid fingerprint";
        Ok(Self(
            kit::Fingerprint::from_str(s).map_err(|_| e)?
        ))
    }
}
