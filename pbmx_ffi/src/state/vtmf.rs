// TODO don't slice if null
// TODO don't transmute if null
// TODO BufferFillPtr copy_from_slice
use crate::{
    buffer::{return_kv_list, BufferFillPtr},
    keys::{PbmxFingerprint, PbmxPrivateKey, PbmxPublicKey},
    opaque::Opaque,
    ptr::PtrOptWrite,
    random::PbmxForeignRng,
    result::PbmxResult,
    state::Pbmx,
};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use digest::XofReader;
use libc::{c_char, size_t};
use pbmx_kit::crypto::{
    map,
    vtmf::{Mask, MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof},
};
use rand::thread_rng;
use std::{
    convert::{TryFrom, TryInto},
    mem,
    ops::Try,
    option::NoneError,
    ptr,
    raw::TraitObject,
    slice, u64,
};

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PbmxToken([u8; 32]);

impl TryFrom<PbmxToken> for RistrettoPoint {
    type Error = NoneError;

    fn try_from(value: PbmxToken) -> Result<Self, Self::Error> {
        Ok(CompressedRistretto::from_slice(&value.0).decompress()?)
    }
}

impl From<RistrettoPoint> for PbmxToken {
    fn from(value: RistrettoPoint) -> Self {
        PbmxToken(value.compress().to_bytes())
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PbmxMask([u8; 32], [u8; 32]);

impl TryFrom<PbmxMask> for Mask {
    type Error = NoneError;

    fn try_from(mask: PbmxMask) -> Result<Self, Self::Error> {
        Ok(Mask(
            CompressedRistretto::from_slice(&mask.0).decompress()?,
            CompressedRistretto::from_slice(&mask.1).decompress()?,
        ))
    }
}
impl From<Mask> for PbmxMask {
    fn from(mask: Mask) -> Self {
        PbmxMask(mask.0.compress().to_bytes(), mask.1.compress().to_bytes())
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct PbmxValue(u64);

impl Try for PbmxValue {
    type Error = NoneError;
    type Ok = u64;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        if self.0 == u64::MAX {
            Err(NoneError)
        } else {
            Ok(self.0)
        }
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self(v)
    }

    fn from_error(_: Self::Error) -> Self {
        Self(u64::MAX)
    }
}

#[no_mangle]
pub extern "C" fn pbmx_encode_token(value: PbmxValue) -> PbmxToken {
    map::to_curve(value.0).into()
}

#[no_mangle]
pub extern "C" fn pbmx_decode_token(token: PbmxToken) -> PbmxValue {
    PbmxValue(map::from_curve(&token.try_into().ok()?))
}

pub type PbmxMaskProof = Opaque<MaskProof>;
ffi_deleter! { pbmx_delete_mask_proof(MaskProof) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_mask(
    state: Pbmx,
    token: PbmxToken,
    mask_out: *mut PbmxMask,
    proof_out: *mut PbmxMaskProof,
) -> PbmxResult {
    let (mask, _, proof) = state.as_ref()?.vtmf.mask(&token.try_into().ok()?);
    mask_out.opt_write(mask.into());
    proof_out.opt_write(Opaque::wrap(proof));
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_verify_mask(
    state: Pbmx,
    token: PbmxToken,
    mask: PbmxMask,
    proof: PbmxMaskProof,
) -> PbmxResult {
    state
        .as_ref()?
        .vtmf
        .verify_mask(
            &token.try_into().ok()?,
            &mask.try_into().ok()?,
            proof.as_ref()?,
        )
        .ok()?;
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_remask(
    state: Pbmx,
    mask: PbmxMask,
    remask_out: *mut PbmxMask,
    proof_out: *mut PbmxMaskProof,
) -> PbmxResult {
    let (remask, _, proof) = state.as_ref()?.vtmf.remask(&mask.try_into().ok()?);
    remask_out.opt_write(remask.into());
    proof_out.opt_write(Opaque::wrap(proof));
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_verify_remask(
    state: Pbmx,
    mask: PbmxMask,
    remask: PbmxMask,
    proof: PbmxMaskProof,
) -> PbmxResult {
    state
        .as_ref()?
        .vtmf
        .verify_remask(
            &mask.try_into().ok()?,
            &remask.try_into().ok()?,
            proof.as_ref()?,
        )
        .ok()?;
    PbmxResult::ok()
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PbmxShare([u8; 32]);

impl TryFrom<PbmxShare> for SecretShare {
    type Error = NoneError;

    fn try_from(value: PbmxShare) -> Result<Self, Self::Error> {
        Ok(CompressedRistretto::from_slice(&value.0).decompress()?)
    }
}
impl From<SecretShare> for PbmxShare {
    fn from(value: SecretShare) -> Self {
        PbmxShare(value.compress().to_bytes())
    }
}

pub type PbmxShareProof = Opaque<SecretShareProof>;
ffi_deleter! { pbmx_delete_share_proof(SecretShareProof) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_share(
    state: Pbmx,
    mask: PbmxMask,
    share_out: *mut PbmxShare,
    proof_out: *mut PbmxShareProof,
) -> PbmxResult {
    let (share, proof) = state.as_ref()?.vtmf.unmask_share(&mask.try_into().ok()?);
    share_out.opt_write(share.into());
    proof_out.opt_write(Opaque::wrap(proof));
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_verify_share(
    state: Pbmx,
    fp: PbmxFingerprint,
    mask: PbmxMask,
    share: PbmxShare,
    proof: PbmxShareProof,
) -> PbmxResult {
    state
        .as_ref()?
        .vtmf
        .verify_unmask(
            &mask.try_into().ok()?,
            &fp,
            &share.try_into().ok()?,
            proof.as_ref()?,
        )
        .ok()?;
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unmask(
    state: Pbmx,
    mask: PbmxMask,
    share: PbmxShare,
    mask_out: *mut PbmxMask,
) -> PbmxResult {
    let mask = state
        .as_ref()?
        .vtmf
        .unmask(&mask.try_into().ok()?, &share.try_into().ok()?);
    mask_out.opt_write(mask.into());
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unmask_private(
    state: Pbmx,
    mask: PbmxMask,
    mask_out: *mut PbmxMask,
) -> PbmxResult {
    let mask = state.as_ref()?.vtmf.unmask_private(&mask.try_into().ok()?);
    mask_out.opt_write(mask.into());
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unmask_open(
    state: Pbmx,
    mask: PbmxMask,
    token_out: *mut PbmxToken,
) -> PbmxResult {
    let token = state.as_ref()?.vtmf.unmask_open(&mask.try_into().ok()?);
    token_out.opt_write(token.into());
    PbmxResult::ok()
}

pub type PbmxShuffleProof = Opaque<ShuffleProof>;
ffi_deleter! { pbmx_delete_shuffle_proof(ShuffleProof) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_shuffle(
    state: Pbmx,
    stack: *const PbmxMask,
    len: size_t,
    perm: *const size_t,
    shuffle_out: *mut PbmxMask,
    proof_out: *mut PbmxShuffleProof,
) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;
    let stack = slice::from_raw_parts(stack, len);
    let perm = slice::from_raw_parts(perm, len);

    let stack: Option<_> = stack.iter().cloned().map(|m| m.try_into().ok()).collect();
    let perm = perm.to_vec().try_into().ok()?;
    let (shuffle, _, proof) = vtmf.mask_shuffle(stack.as_ref()?, &perm);

    let mut shuffle_out = BufferFillPtr::new(shuffle_out)?;
    for mask in shuffle.iter().cloned() {
        shuffle_out.push(mask.into());
    }
    proof_out.opt_write(Opaque::wrap(proof));
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_verify_shuffle(
    state: Pbmx,
    stack: *const PbmxMask,
    len: size_t,
    shuffle: *const PbmxMask,
    proof: PbmxShuffleProof,
) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;
    let stack = slice::from_raw_parts(stack, len);
    let shuffle = slice::from_raw_parts(shuffle, len);
    let stack = stack
        .iter()
        .cloned()
        .map(|m| m.try_into().ok())
        .collect::<Option<_>>()?;
    let shuffle = shuffle
        .iter()
        .cloned()
        .map(|m| m.try_into().ok())
        .collect::<Option<_>>()?;
    vtmf.verify_mask_shuffle(&stack, &shuffle, proof.as_ref()?)
        .ok()?;
    PbmxResult::ok()
}

pub type PbmxShiftProof = Opaque<ShiftProof>;
ffi_deleter! { pbmx_delete_shift_proof(ShiftProof) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_shift(
    state: Pbmx,
    stack: *const PbmxMask,
    len: size_t,
    k: size_t,
    shift_out: *mut PbmxMask,
    proof_out: *mut PbmxShiftProof,
) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;
    let stack = slice::from_raw_parts(stack, len);

    let stack: Option<_> = stack.iter().cloned().map(|m| m.try_into().ok()).collect();
    let (shift, _, proof) = vtmf.mask_shift(stack.as_ref()?, k);

    let mut shift_out = BufferFillPtr::new(shift_out)?;
    for mask in shift.iter().cloned() {
        shift_out.push(mask.into());
    }
    proof_out.opt_write(Opaque::wrap(proof));
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_verify_shift(
    state: Pbmx,
    stack: *const PbmxMask,
    len: size_t,
    shift: *const PbmxMask,
    proof: PbmxShiftProof,
) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;
    let stack = slice::from_raw_parts(stack, len);
    let shift = slice::from_raw_parts(shift, len);
    let stack = stack
        .iter()
        .cloned()
        .map(|m| m.try_into().ok())
        .collect::<Option<_>>()?;
    let shift = shift
        .iter()
        .cloned()
        .map(|m| m.try_into().ok())
        .collect::<Option<_>>()?;
    vtmf.verify_mask_shift(&stack, &shift, proof.as_ref()?)
        .ok()?;
    PbmxResult::ok()
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct PbmxXof(TraitObject);

impl PbmxXof {
    unsafe fn wrap<T>(reader: T) -> Self
    where
        T: XofReader + 'static,
    {
        let boxed: Box<dyn XofReader> = box reader;
        Self(mem::transmute(Box::into_raw(boxed)))
    }

    fn is_null(&self) -> bool {
        self.0.data.is_null() || self.0.vtable.is_null()
    }

    unsafe fn as_mut(&mut self) -> Option<&mut dyn XofReader> {
        if self.is_null() {
            None
        } else {
            Some(mem::transmute(self.0))
        }
    }

    unsafe fn delete(mut self) {
        if let Some(r) = self.as_mut() {
            let _: Box<dyn XofReader> = Box::from_raw(r);
        }
    }
}

impl Try for PbmxXof {
    type Error = NoneError;
    type Ok = TraitObject;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        if self.is_null() {
            Err(NoneError)
        } else {
            Ok(self.0)
        }
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self(v)
    }

    fn from_error(_: Self::Error) -> Self {
        Self(TraitObject {
            data: ptr::null_mut(),
            vtable: ptr::null_mut(),
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_mask_random(
    state: Pbmx,
    rng: *mut PbmxForeignRng,
    mask_out: *mut PbmxMask,
) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;

    let mask = if rng.is_null() {
        vtmf.mask_random(&mut thread_rng())
    } else {
        vtmf.mask_random(&mut *rng)
    };
    mask_out.opt_write(mask.into());
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_add_masks(
    mask1: PbmxMask,
    mask2: PbmxMask,
    mask_out: *mut PbmxMask,
) -> PbmxResult {
    let mask1: Mask = mask1.try_into().ok()?;
    let mask2: Mask = mask2.try_into().ok()?;
    mask_out.opt_write((mask1 + mask2).into());
    PbmxResult::ok()
}

#[no_mangle]
#[allow(improper_ctypes)]
pub unsafe extern "C" fn pbmx_unmask_random(
    state: Pbmx,
    mask: PbmxMask,
    xof_out: *mut PbmxXof,
) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;
    let xof = PbmxXof::wrap(vtmf.unmask_random(&mask.try_into().ok()?));
    xof_out.write(xof);
    PbmxResult::ok()
}

#[no_mangle]
#[allow(improper_ctypes)]
pub unsafe extern "C" fn pbmx_read_xof(mut xof: PbmxXof, buf: *mut u8, len: size_t) -> PbmxResult {
    let buf = slice::from_raw_parts_mut(buf, len);
    xof.as_mut()?.read(buf);
    PbmxResult::ok()
}

#[no_mangle]
#[allow(improper_ctypes)]
pub unsafe extern "C" fn pbmx_delete_xof(xof: PbmxXof) {
    xof.delete();
}
