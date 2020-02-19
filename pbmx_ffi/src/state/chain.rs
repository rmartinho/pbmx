use crate::{
    buffer::{return_list, return_string},
    keys::{PbmxFingerprint, PbmxPublicKey},
    opaque::Opaque,
    ptr::PtrOptWrite,
    result::PbmxResult,
    state::{
        vtmf::{
            PbmxDisjointProof, PbmxEntanglementProof, PbmxMask, PbmxMaskProof, PbmxShare,
            PbmxShareProof, PbmxShiftProof, PbmxShuffleProof, PbmxSubsetProof, PbmxSupersetProof,
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
pub unsafe extern "C" fn pbmx_prove_entanglement_payload(
    mut builder: PbmxBlockBuilder,
    sources: *const PbmxFingerprint,
    len: size_t,
    shuffles: *const PbmxFingerprint,
    proof: PbmxEntanglementProof,
) -> PbmxResult {
    let sources = slice::from_raw_parts(sources, len);
    let sources: Option<Vec<_>> = sources.iter().cloned().map(|s| s.try_into().ok()).collect();
    let shuffles = slice::from_raw_parts(shuffles, len);
    let shuffles: Option<Vec<_>> = shuffles
        .iter()
        .cloned()
        .map(|s| s.try_into().ok())
        .collect();
    let payload =
        Payload::ProveEntanglement(sources?.into(), shuffles?.into(), proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_prove_subset_payload(
    mut builder: PbmxBlockBuilder,
    sub: PbmxFingerprint,
    sup: PbmxFingerprint,
    proof: PbmxSubsetProof,
) -> PbmxResult {
    let payload = Payload::ProveSubset(sub, sup, proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_prove_superset_payload(
    mut builder: PbmxBlockBuilder,
    sup: PbmxFingerprint,
    sub: PbmxFingerprint,
    proof: PbmxSupersetProof,
) -> PbmxResult {
    let payload = Payload::ProveSuperset(sup, sub, proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_prove_disjoint_payload(
    mut builder: PbmxBlockBuilder,
    id1: PbmxFingerprint,
    id2: PbmxFingerprint,
    sup: PbmxFingerprint,
    proof: PbmxDisjointProof,
) -> PbmxResult {
    let payload = Payload::ProveDisjoint(id1, id2, sup, proof.as_ref().cloned()?);
    builder.as_mut()?.add_payload(payload);
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_text_payload(
    mut builder: PbmxBlockBuilder,
    text: *const c_char,
) -> PbmxResult {
    let text = CStr::from_ptr(text).to_string_lossy();
    let payload = Payload::Text(text.into());
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
        .map(|b| Opaque::wrap(b.clone()));
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
    let payloads = block.as_ref()?.payloads().map(|p| Opaque::wrap(p.clone()));
    return_list(payloads, ptr, len)
}

#[repr(C)]
pub enum PayloadKind {
    PublishKey = 1,
    OpenStack,
    HiddenStack,
    MaskStack,
    ShuffleStack,
    ShiftStack,
    NameStack,
    TakeStack,
    PileStacks,
    PublishShares,
    RandomSpec,
    RandomEntropy,
    RandomReveal,
    ProveEntanglement,
    ProveSubset,
    ProveSuperset,
    ProveDisjoint,
    Text,
    Bytes,
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_payload_kind(
    payload: PbmxPayload,
    kind_out: *mut PayloadKind,
) -> PbmxResult {
    kind_out.opt_write(match payload.as_ref()? {
        Payload::PublishKey(..) => PayloadKind::PublishKey,
        Payload::OpenStack(_) => PayloadKind::OpenStack,
        Payload::HiddenStack(_) => PayloadKind::HiddenStack,
        Payload::MaskStack(..) => PayloadKind::MaskStack,
        Payload::ShuffleStack(..) => PayloadKind::ShuffleStack,
        Payload::ShiftStack(..) => PayloadKind::ShiftStack,
        Payload::NameStack(..) => PayloadKind::NameStack,
        Payload::TakeStack(..) => PayloadKind::TakeStack,
        Payload::PileStacks(..) => PayloadKind::PileStacks,
        Payload::PublishShares(..) => PayloadKind::PublishShares,
        Payload::RandomSpec(..) => PayloadKind::RandomSpec,
        Payload::RandomEntropy(..) => PayloadKind::RandomEntropy,
        Payload::RandomReveal(..) => PayloadKind::RandomReveal,
        Payload::ProveEntanglement(..) => PayloadKind::ProveEntanglement,
        Payload::ProveSubset(..) => PayloadKind::ProveSubset,
        Payload::ProveSuperset(..) => PayloadKind::ProveSuperset,
        Payload::ProveDisjoint(..) => PayloadKind::ProveDisjoint,
        Payload::Text(_) => PayloadKind::Text,
        Payload::Bytes(_) => PayloadKind::Bytes,
    });
    PbmxResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_publish_key(
    payload: PbmxPayload,
    name_out: *mut c_char,
    name_len: *mut size_t,
    key_out: *mut PbmxPublicKey,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::PublishKey(name, key) => {
            return_string(&name, name_out, name_len)?;
            key_out.opt_write(Opaque::wrap(key.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_open_stack(
    payload: PbmxPayload,
    masks_out: *mut PbmxMask,
    len: *mut size_t,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::OpenStack(stack) => {
            let masks = stack.iter().map(|&m| m.into());
            return_list(masks, masks_out, len)?;
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_mask_stack(
    payload: PbmxPayload,
    id_out: *mut PbmxFingerprint,
    masks_out: *mut PbmxMask,
    len: *mut size_t,
    proofs_out: *mut PbmxMaskProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::MaskStack(id, stack, proof) => {
            let masks = stack.iter().map(|&m| m.into());
            return_list(masks, masks_out, len)?;
            let proofs = proof.iter().map(|p| Opaque::wrap(p.clone()));
            return_list(proofs, proofs_out, len)?;
            id_out.opt_write(id.clone().into());
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_shuffle_stack(
    payload: PbmxPayload,
    id_out: *mut PbmxFingerprint,
    masks_out: *mut PbmxMask,
    len: *mut size_t,
    proof_out: *mut PbmxShuffleProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::ShuffleStack(id, stack, proof) => {
            let masks = stack.iter().map(|&m| m.into());
            return_list(masks, masks_out, len)?;
            id_out.opt_write(id.clone().into());
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_shift_stack(
    payload: PbmxPayload,
    id_out: *mut PbmxFingerprint,
    masks_out: *mut PbmxMask,
    len: *mut size_t,
    proof_out: *mut PbmxShiftProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::ShiftStack(id, stack, proof) => {
            let masks = stack.iter().map(|&m| m.into());
            return_list(masks, masks_out, len)?;
            id_out.opt_write(id.clone().into());
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_name_stack(
    payload: PbmxPayload,
    id_out: *mut PbmxFingerprint,
    name_out: *mut c_char,
    name_len: *mut size_t,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::NameStack(id, name) => {
            return_string(name, name_out, name_len)?;
            id_out.opt_write(id.clone().into());
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_take_stack(
    payload: PbmxPayload,
    id1_out: *mut PbmxFingerprint,
    indices_out: *mut size_t,
    indices_len: *mut size_t,
    id2_out: *mut PbmxFingerprint,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::TakeStack(id1, indices, id2) => {
            return_list(indices.iter().cloned(), indices_out, indices_len)?;
            id1_out.opt_write(id1.clone().into());
            id2_out.opt_write(id2.clone().into());
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_pile_stacks(
    payload: PbmxPayload,
    ids_out: *mut PbmxFingerprint,
    ids_len: *mut size_t,
    id_out: *mut PbmxFingerprint,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::PileStacks(ids, id) => {
            return_list(ids.iter().cloned(), ids_out, ids_len)?;
            id_out.opt_write(id.clone().into());
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_publish_shares(
    payload: PbmxPayload,
    id_out: *mut PbmxFingerprint,
    shares_out: *mut PbmxShare,
    len: *mut size_t,
    proofs_out: *mut PbmxShareProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::PublishShares(id, shares, proofs) => {
            let shares = shares.iter().map(|&m| m.into());
            return_list(shares, shares_out, len)?;
            let proofs = proofs.iter().map(|p| Opaque::wrap(p.clone()));
            return_list(proofs, proofs_out, len)?;
            id_out.opt_write(id.clone().into());
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_random_spec(
    payload: PbmxPayload,
    name_out: *mut c_char,
    name_len: *mut size_t,
    spec_out: *mut c_char,
    spec_len: *mut size_t,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::RandomSpec(name, spec) => {
            return_string(name, name_out, name_len)?;
            return_string(spec, spec_out, spec_len)?;
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_random_entropy(
    payload: PbmxPayload,
    name_out: *mut c_char,
    name_len: *mut size_t,
    entropy_out: *mut PbmxMask,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::RandomEntropy(name, entropy) => {
            return_string(name, name_out, name_len)?;
            entropy_out.opt_write(entropy.clone().into());
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_random_reveal(
    payload: PbmxPayload,
    name_out: *mut c_char,
    name_len: *mut size_t,
    share_out: *mut PbmxShare,
    proof_out: *mut PbmxShareProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::RandomReveal(name, share, proof) => {
            return_string(name, name_out, name_len)?;
            share_out.opt_write(share.clone().into());
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_prove_entanglement(
    payload: PbmxPayload,
    sources_out: *mut PbmxFingerprint,
    len: *mut size_t,
    shuffles_out: *mut PbmxFingerprint,
    proof_out: *mut PbmxEntanglementProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::ProveEntanglement(sources, shuffles, proof) => {
            let sources = sources.iter().map(|&m| m.into());
            return_list(sources, sources_out, len)?;
            let shuffles = shuffles.iter().map(|&m| m.into());
            return_list(shuffles, shuffles_out, len)?;
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}
#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_prove_subset(
    payload: PbmxPayload,
    sub_out: *mut PbmxFingerprint,
    sup_out: *mut PbmxFingerprint,
    proof_out: *mut PbmxSubsetProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::ProveSubset(sub, sup, proof) => {
            sub_out.opt_write(sub.clone().into());
            sup_out.opt_write(sup.clone().into());
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}
#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_prove_superset(
    payload: PbmxPayload,
    sup_out: *mut PbmxFingerprint,
    sub_out: *mut PbmxFingerprint,
    proof_out: *mut PbmxSupersetProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::ProveSuperset(sup, sub, proof) => {
            sup_out.opt_write(sup.clone().into());
            sub_out.opt_write(sub.clone().into());
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}
#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_prove_disjoint(
    payload: PbmxPayload,
    id1_out: *mut PbmxFingerprint,
    id2_out: *mut PbmxFingerprint,
    sup_out: *mut PbmxFingerprint,
    proof_out: *mut PbmxDisjointProof,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::ProveDisjoint(id1, id2, sup, proof) => {
            id1_out.opt_write(id1.clone().into());
            id2_out.opt_write(id2.clone().into());
            sup_out.opt_write(sup.clone().into());
            proof_out.opt_write(Opaque::wrap(proof.clone()));
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_text(
    payload: PbmxPayload,
    buf_out: *mut u8,
    len: *mut size_t,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::Text(text) => {
            return_list(text.as_bytes().iter().cloned(), buf_out, len)?;
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pbmx_unwrap_bytes(
    payload: PbmxPayload,
    buf_out: *mut u8,
    len: *mut size_t,
) -> PbmxResult {
    match payload.as_ref()? {
        Payload::Bytes(bytes) => {
            return_list(bytes.iter().cloned(), buf_out, len)?;
            PbmxResult::ok()
        }
        _ => PbmxResult::err(),
    }
}
