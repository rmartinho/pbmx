use crate::{
    keys::{PbmxFingerprint, PbmxPublicKey},
    opaque::Opaque,
    result::PbmxResult,
    state::{
        vtmf::{
            PbmxInsertProof, PbmxMask, PbmxMaskProof, PbmxShare, PbmxShareProof, PbmxShiftProof,
            PbmxShuffleProof,
        },
        Pbmx,
    },
};
use libc::{c_char, c_int, size_t};
use pbmx_kit::{
    chain::{Block, BlockBuilder, Payload},
    crypto::vtmf::Mask,
};
use std::{convert::TryInto, ffi::CStr, slice};

pub type PbmxBlock = Opaque<Block>;
ffi_deleter! { pbmx_delete_block(Block) }
ffi_serde!(Block: pbmx_export_block pbmx_import_block);

#[no_mangle]
pub unsafe extern "C" fn pbmx_add_block(mut state: Pbmx, block: PbmxBlock) -> PbmxResult {
    state.as_mut()?.add_block(block.as_ref()?).ok()?;
    PbmxResult::ok()
}

pub type PbmxBlockBuilder = Opaque<BlockBuilder>;
ffi_deleter! { pbmx_delete_block_builder(BlockBuilder) }

#[no_mangle]
pub unsafe extern "C" fn pbmx_block_builder(mut state: Pbmx) -> PbmxBlockBuilder {
    Opaque::wrap(state.as_mut()?.chain.build_block())
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_build_block(state: Pbmx, builder: PbmxBlockBuilder) -> PbmxBlock {
    let builder = builder.boxed()?;
    let sk = state.as_ref()?.vtmf.private_key();
    Opaque::wrap(builder.build(&sk))
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_publish_key_payload(
    mut builder: PbmxBlockBuilder,
    name: *const c_char,
    key: PbmxPublicKey,
) -> PbmxResult {
    let name = CStr::from_ptr(name).to_string_lossy();
    let key = key.as_ref()?.clone();
    let payload = Payload::PublishKey(name.into(), key);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_open_stack_payload(
    mut builder: PbmxBlockBuilder,
    masks: *const PbmxMask,
    len: size_t,
) -> PbmxResult {
    let masks = slice::from_raw_parts(masks, len);
    let stack: Option<Vec<_>> = masks.iter().cloned().map(|m| m.try_into().ok()).collect();
    let payload = Payload::OpenStack(stack?.into());
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_mask_stack_payload(
    mut builder: PbmxBlockBuilder,
    id: PbmxFingerprint,
    masks: *const PbmxMask,
    len: size_t,
    proofs: *const PbmxMaskProof,
) -> PbmxResult {
    let masks = slice::from_raw_parts(masks, len);
    let proofs = slice::from_raw_parts(proofs, len);
    let stack: Option<Vec<_>> = masks.iter().cloned().map(|m| m.try_into().ok()).collect();
    let proof: Option<Vec<_>> = proofs.iter().map(|p| p.as_ref().cloned()).collect();
    let payload = Payload::MaskStack(id, stack?.into(), proof?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_shuffle_stack_payload(
    mut builder: PbmxBlockBuilder,
    id: PbmxFingerprint,
    masks: *const PbmxMask,
    len: size_t,
    proof: PbmxShuffleProof,
) -> PbmxResult {
    let masks = slice::from_raw_parts(masks, len);
    let stack: Option<Vec<_>> = masks.iter().cloned().map(|m| m.try_into().ok()).collect();
    let payload = Payload::ShuffleStack(id, stack?.into(), proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_shift_stack_payload(
    mut builder: PbmxBlockBuilder,
    id: PbmxFingerprint,
    masks: *const PbmxMask,
    len: size_t,
    proof: PbmxShiftProof,
) -> PbmxResult {
    let masks = slice::from_raw_parts(masks, len);
    let stack: Option<Vec<_>> = masks.iter().cloned().map(|m| m.try_into().ok()).collect();
    let payload = Payload::ShiftStack(id, stack?.into(), proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_name_stack_payload(
    mut builder: PbmxBlockBuilder,
    id: PbmxFingerprint,
    name: *const c_char,
) -> PbmxResult {
    let name = CStr::from_ptr(name).to_string_lossy();
    let payload = Payload::NameStack(id, name.into());
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_take_stack_payload(
    mut builder: PbmxBlockBuilder,
    id1: PbmxFingerprint,
    indices: *const size_t,
    len: size_t,
    id2: PbmxFingerprint,
) -> PbmxResult {
    let indices = slice::from_raw_parts(indices, len);
    let payload = Payload::TakeStack(id1, indices.into(), id2);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_pile_stacks_payload(
    mut builder: PbmxBlockBuilder,
    ids: *const PbmxFingerprint,
    len: size_t,
    id: PbmxFingerprint,
) -> PbmxResult {
    let ids = slice::from_raw_parts(ids, len);
    let payload = Payload::PileStacks(ids.into(), id);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_insert_stack_payload(
    mut builder: PbmxBlockBuilder,
    id1: PbmxFingerprint,
    id2: PbmxFingerprint,
    masks: *const PbmxMask,
    len: size_t,
    proof: PbmxInsertProof,
) -> PbmxResult {
    let masks = slice::from_raw_parts(masks, len);
    let stack: Option<Vec<_>> = masks.iter().cloned().map(|m| m.try_into().ok()).collect();
    let payload = Payload::InsertStack(id1, id2, stack?.into(), proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_publish_shares_payload(
    mut builder: PbmxBlockBuilder,
    id: PbmxFingerprint,
    shares: *const PbmxShare,
    len: size_t,
    proofs: *const PbmxShareProof,
) -> PbmxResult {
    let shares = slice::from_raw_parts(shares, len);
    let proofs = slice::from_raw_parts(proofs, len);
    let stack: Option<Vec<_>> = shares.iter().cloned().map(|m| m.try_into().ok()).collect();
    let proof: Option<Vec<_>> = proofs.iter().map(|p| p.as_ref().cloned()).collect();
    let payload = Payload::PublishShares(id, stack?.into(), proof?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_random_spec_payload(
    mut builder: PbmxBlockBuilder,
    name: *const c_char,
    spec: *const c_char,
) -> PbmxResult {
    let name = CStr::from_ptr(name).to_string_lossy();
    let spec = CStr::from_ptr(spec).to_string_lossy();
    let payload = Payload::RandomSpec(name.into(), spec.into());
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_random_entropy_payload(
    mut builder: PbmxBlockBuilder,
    name: *const c_char,
    entropy: PbmxMask,
) -> PbmxResult {
    let name = CStr::from_ptr(name).to_string_lossy();
    let payload = Payload::RandomEntropy(name.into(), entropy.try_into().ok()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_random_reveal_payload(
    mut builder: PbmxBlockBuilder,
    name: *const c_char,
    share: PbmxShare,
    proof: PbmxShareProof,
) -> PbmxResult {
    let name = CStr::from_ptr(name).to_string_lossy();
    let payload = Payload::RandomReveal(
        name.into(),
        share.try_into().ok()?,
        proof.as_ref().cloned()?,
    );
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_bytes_payload(
    mut builder: PbmxBlockBuilder,
    buf: *const u8,
    len: size_t,
) -> PbmxResult {
    let slice = slice::from_raw_parts(buf, len);
    let payload = Payload::Bytes(slice.into());
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_stack_id(stack: *const PbmxMask, len: size_t) -> PbmxFingerprint {
    let masks = slice::from_raw_parts(stack, len);
    let stack: Option<_> = masks.iter().cloned().map(|m| m.try_into().ok()).collect();
    stack
        .as_ref()
        .and_then(|s: &Vec<Mask>| PbmxFingerprint::of(s).ok())
        .unwrap_or_else(Default::default)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_block_id(block: PbmxBlock) -> PbmxFingerprint {
    block
        .as_ref()
        .map(|b| b.id())
        .unwrap_or_else(Default::default)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_block_signer(block: PbmxBlock) -> PbmxFingerprint {
    block
        .as_ref()
        .map(|b| b.signer())
        .unwrap_or_else(Default::default)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_block_validate(state: Pbmx, block: PbmxBlock) -> PbmxResult {
    let vtmf = &state.as_ref()?.vtmf;
    let block = block.as_ref()?;
    let pki = vtmf
        .public_keys()
        .map(|pk| (pk.fingerprint(), pk))
        .collect();
    if block.is_valid(&pki).is_true() {
        PbmxResult::ok()
    } else {
        PbmxResult::err()
    }
}

pub unsafe fn return_list<T, It>(iter: It, ptr: *mut T, len: *mut size_t) -> PbmxResult
where
    It: ExactSizeIterator<Item = T>,
{
    let len = &mut *len;
    let n = iter.len();
    if *len < n {
        *len = n;
        return PbmxResult::ok();
    }

    if ptr.is_null() {
        return None?;
    }

    let slice = slice::from_raw_parts_mut(ptr, *len);
    for (t, s) in iter.zip(slice.iter_mut()) {
        *s = t;
    }

    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_blocks(
    state: Pbmx,
    ptr: *mut PbmxBlock,
    len: *mut size_t,
) -> PbmxResult {
    let blocks = state
        .as_ref()?
        .chain
        .blocks()
        .map(|b| PbmxBlock::wrap(b.clone()));
    return_list(blocks, ptr, len)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_heads(
    state: Pbmx,
    ptr: *mut PbmxFingerprint,
    len: *mut size_t,
) -> PbmxResult {
    let heads = state.as_ref()?.chain.heads().iter().cloned();
    return_list(heads, ptr, len)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_roots(
    state: Pbmx,
    ptr: *mut PbmxFingerprint,
    len: *mut size_t,
) -> PbmxResult {
    let roots = state.as_ref()?.chain.roots().iter().cloned();
    return_list(roots, ptr, len)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_merged_chain(state: Pbmx) -> c_int {
    state
        .as_ref()
        .map(|s| if s.chain.is_merged() { 1 } else { 0 })
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_empty_chain(state: Pbmx) -> c_int {
    state
        .as_ref()
        .map(|s| if s.chain.is_empty() { 1 } else { 0 })
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_incomplete_chain(state: Pbmx) -> c_int {
    state
        .as_ref()
        .map(|s| if s.chain.is_incomplete() { 1 } else { 0 })
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_parent_ids(
    block: PbmxBlock,
    ptr: *mut PbmxFingerprint,
    len: *mut size_t,
) -> PbmxResult {
    let ids = block.as_ref()?.parent_ids().iter().cloned();
    return_list(ids, ptr, len)
}

pub type PbmxPayload = Opaque<Payload>;

#[no_mangle]
pub unsafe extern "C" fn pbmx_payloads(
    block: PbmxBlock,
    ptr: *mut PbmxPayload,
    len: *mut size_t,
) -> PbmxResult {
    let payloads = block
        .as_ref()?
        .payloads()
        .map(|p| PbmxPayload::wrap(p.clone()));
    return_list(payloads, ptr, len)
}
