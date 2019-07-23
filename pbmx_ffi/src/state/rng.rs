use crate::{
    buffer::{return_kv_list, return_list, return_string},
    keys::PbmxFingerprint,
    opaque::Opaque,
    ptr::PtrOptWrite,
    result::PbmxResult,
    state::{
        vtmf::{PbmxMask, PbmxShare},
        Pbmx,
    },
};
use libc::{c_char, c_int, size_t};
use pbmx_kit::state::Rng;
use std::convert::TryInto;

pub type PbmxRng = Opaque<Rng>;
ffi_deleter! { pbmx_delete_rng(Rng) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_rngs(
    state: Pbmx,
    names_idx_out: *mut size_t,
    len: *mut size_t,
    names_out: *mut c_char,
    names_len: *mut size_t,
    rngs_out: *mut PbmxRng,
) -> PbmxResult {
    let map = &state.as_ref()?.rngs;
    let pairs = map
        .iter()
        .map(|(k, v)| (k.clone(), Opaque::wrap(v.clone())));
    return_kv_list(pairs, names_idx_out, len, names_out, names_len, rngs_out)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_spec(
    rng: PbmxRng,
    spec_out: *mut c_char,
    len: *mut size_t,
) -> PbmxResult {
    return_string(&rng.as_ref()?.spec(), spec_out, len)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_mask(rng: PbmxRng, mask_out: *mut PbmxMask) -> PbmxResult {
    mask_out.opt_write(rng.as_ref()?.mask().clone().into());
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_add_entropy(
    mut rng: PbmxRng,
    party: PbmxFingerprint,
    mask: PbmxMask,
) -> PbmxResult {
    rng.as_mut()?.add_entropy(party, &mask.try_into().ok()?);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_add_secret(
    mut rng: PbmxRng,
    party: PbmxFingerprint,
    share: PbmxShare,
) -> PbmxResult {
    rng.as_mut()?.add_secret(party, &share.try_into().ok()?);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_entropy_parties(
    rng: PbmxRng,
    fps_out: *mut PbmxFingerprint,
    len: *mut size_t,
) -> PbmxResult {
    let fps = rng.as_ref()?.entropy_parties();
    return_list(fps.iter().cloned(), fps_out, len)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_secret_parties(
    rng: PbmxRng,
    fps_out: *mut PbmxFingerprint,
    len: *mut size_t,
) -> PbmxResult {
    let fps = rng.as_ref()?.secret_parties();
    return_list(fps.iter().cloned(), fps_out, len)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_generated(rng: PbmxRng) -> c_int {
    rng.as_ref()
        .map(|r| if r.is_generated() { 1 } else { 0 })
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_revealed(rng: PbmxRng) -> c_int {
    rng.as_ref()
        .map(|r| if r.is_revealed() { 1 } else { 0 })
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_rng_gen(state: Pbmx, rng: PbmxRng, val: *mut u64) -> PbmxResult {
    val.opt_write(rng.as_ref()?.gen(&state.as_ref()?.vtmf));
    PbmxResult::ok()
}
