use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use pbmx_kit::random::thread_rng;
use wasm_bindgen::prelude::*;

use pbmx_kit::crypto::vtmf as kit;

#[wasm_bindgen]
#[repr(transparent)]
pub struct Vtmf(pub(crate) kit::Vtmf);

#[wasm_bindgen]
impl Vtmf {
    pub fn new(sk: &PrivateKey) -> Self {
        Self(kit::Vtmf::new(sk.0.clone()))
    }

    pub fn private_key(&self) -> PrivateKey {
        PrivateKey(self.0.private_key())
    }

    pub fn shared_key(&self) -> PublicKey {
        PublicKey(self.0.shared_key())
    }
}

#[cfg(x)]
mod x {
#[no_mangle]
pub unsafe extern "C" fn pbmx_private_key(state: Pbmx) -> PbmxPrivateKey {
    Opaque::wrap(state.as_ref()?.vtmf.private_key())
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_shared_key(state: Pbmx) -> PbmxPublicKey {
    Opaque::wrap(state.as_ref()?.vtmf.shared_key())
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_add_key(mut state: Pbmx, key: PbmxPublicKey) -> PbmxResult {
    let vtmf = &mut state.as_mut()?.vtmf;
    let key = key.as_ref()?;
    vtmf.add_key(key.clone());
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_parties(
    state: Pbmx,
    fp_out: *mut PbmxFingerprint,
    len: *mut size_t,
    names_idx_out: *mut size_t,
    names_out: *mut c_char,
    names_len: *mut size_t,
) -> PbmxResult {
    let map = &state.as_ref()?.names;
    return_kv_list(
        map.iter().map(|(k, v)| (v.clone(), k.clone())),
        names_idx_out,
        len,
        names_out,
        names_len,
        fp_out,
    )
}
}
