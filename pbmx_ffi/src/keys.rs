use crate::{opaque::Opaque, random::PbmxForeignRng};
use pbmx_kit::crypto::keys::{Fingerprint, PrivateKey, PublicKey};
use rand::thread_rng;

pub type PbmxPrivateKey = Opaque<PrivateKey>;
ffi_deleter! { pbmx_delete_private_key(PbmxPrivateKey) }

pub type PbmxPublicKey = Opaque<PublicKey>;
ffi_deleter! { pbmx_delete_public_key(PbmxPublicKey) }

pub type PbmxFingerprint = Fingerprint;

#[no_mangle]
pub unsafe extern "C" fn pbmx_random_key(rng: *mut PbmxForeignRng) -> PbmxPrivateKey {
    Opaque::wrap(if rng.is_null() {
        PrivateKey::random(&mut thread_rng())
    } else {
        PrivateKey::random(&mut *rng)
    })
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_public_key(key: PbmxPrivateKey) -> PbmxPublicKey {
    Opaque::wrap(key.as_ref()?.public_key())
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_key_fingerprint(key: PbmxPublicKey) -> PbmxFingerprint {
    key.as_ref()
        .map(|k| k.fingerprint())
        .unwrap_or_else(Default::default)
}

ffi_serde!(PrivateKey: pbmx_export_private_key pbmx_import_private_key);
