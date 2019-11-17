package io.rmf.pbmx.ffi

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import java.nio.ByteBuffer

@Suppress("FunctionName")
interface LibPbmx : Library {

    fun pbmx_new(key: Pointer): Pointer
    fun pbmx_delete(key: Pointer)

    fun pbmx_random_key(rng: Pointer?): Pointer
    fun pbmx_delete_private_key(key: Pointer)
    fun pbmx_public_key(key: Pointer): Pointer
    fun pbmx_delete_public_key(key: Pointer)
    fun pbmx_key_fingerprint(key: Pointer): RawFingerprint.ByValue
    fun pbmx_export_private_key(key: Pointer, buf: ByteBuffer?, len: LongByReference): Int
    fun pbmx_import_private_key(buf: ByteBuffer, len: Long): Pointer

    fun pbmx_private_key(pbmx: Pointer): Pointer
    fun pbmx_shared_key(pbmx: Pointer): Pointer
    fun pbmx_add_key(pbmx: Pointer, key: Pointer)
    fun pbmx_parties(
        pbmx: Pointer,
        outFingerprints: Array<RawFingerprint>?,
        len: LongByReference,
        outNameIdx: LongArray?,
        outNames: ByteArray?,
        namesLen: LongByReference
    ): Int

    fun pbmx_encode_token(value: Long): RawToken.ByValue
    fun pbmx_decode_token(token: RawToken.ByValue): Long

    fun pbmx_mask(pbmx: Pointer, token: RawToken.ByValue, outMask: RawMask, outProof: PointerByReference): Int
    fun pbmx_verify_mask(pbmx: Pointer, token: RawToken.ByValue, mask: RawMask.ByValue, proof: Pointer): Int
    fun pbmx_delete_mask_proof(proof: Pointer)

    fun pbmx_remask(pbmx: Pointer, mask: RawMask.ByValue, outRemask: RawMask, outProof: PointerByReference): Int
    fun pbmx_verify_remask(pbmx: Pointer, mask: RawMask.ByValue, remask: RawMask.ByValue, proof: Pointer): Int

    fun pbmx_share(pbmx: Pointer, mask: RawMask.ByValue, outShare: RawShare, outProof: PointerByReference): Int
    fun pbmx_verify_share(
        pbmx: Pointer,
        fp: RawFingerprint.ByValue,
        mask: RawMask.ByValue,
        share: RawShare.ByValue,
        proof: Pointer
    ): Int

    fun pbmx_delete_share_proof(proof: Pointer)

    fun pbmx_unmask(pbmx: Pointer, mask: RawMask.ByValue, share: RawShare.ByValue, outMask: RawMask): Int
    fun pbmx_unmask_private(pbmx: Pointer, mask: RawMask.ByValue, outMask: RawMask): Int
    fun pbmx_unmask_open(pbmx: Pointer, mask: RawMask.ByValue, outToken: RawToken): Int

    fun pbmx_shuffle(
        pbmx: Pointer,
        stack: Array<RawMask>,
        len: Long,
        perm: LongArray,
        outShuffle: Array<RawMask>,
        outSecrets: Array<RawScalar>,
        outProof: PointerByReference
    ): Int

    fun pbmx_verify_shuffle(
        pbmx: Pointer,
        stack: Array<RawMask>,
        len: Long,
        shuffle: Array<RawMask>,
        proof: Pointer
    ): Int

    fun pbmx_delete_shuffle_proof(proof: Pointer)

    fun pbmx_shift(
        pbmx: Pointer,
        stack: Array<RawMask>,
        len: Long,
        k: Long,
        outShift: Array<RawMask>,
        outSecrets: Array<RawScalar>,
        outProof: PointerByReference
    ): Int

    fun pbmx_verify_shift(pbmx: Pointer, stack: Array<RawMask>, len: Long, shift: Array<RawMask>, proof: Pointer): Int
    fun pbmx_delete_shift_proof(proof: Pointer)

    fun pbmx_random_permutation(rng: Pointer?, len: Long, outPerm: LongArray): Int
    fun pbmx_random_shift(rng: Pointer?, len: Long, outK: LongByReference): Int

    fun pbmx_mask_random(pbmx: Pointer, rng: Pointer?, outMask: RawMask): Int
    fun pbmx_add_masks(mask1: RawMask.ByValue, mask2: RawMask.ByValue, outMask: RawMask): Int
    fun pbmx_unmask_random(pbmx: Pointer, mask: RawMask.ByValue, outXof: RawXof): Int

    fun pbmx_read_xof(xof: RawXof.ByValue, buf: ByteBuffer, len: Long): Int
    fun pbmx_delete_xof(xof: RawXof.ByValue)

    fun pbmx_prove_entanglement(
        pbmx: Pointer,
        sources: Array<RawMask>,
        nStacks: Long,
        stackLen: Long,
        shuffles: Array<RawMask>,
        perm: LongArray,
        secrets: Array<RawScalar>,
        outProof: PointerByReference
    ): Int

    fun pbmx_verify_entanglement(
        pbmx: Pointer,
        sources: Array<RawMask>,
        nStacks: Long,
        stackLen: Long,
        shuffles: Array<RawMask>,
        proof: Pointer
    ): Int

    fun pbmx_delete_entanglement_proof(proof: Pointer)

    fun pbmx_add_block(pbmx: Pointer, block: Pointer): Int
    fun pbmx_delete_block(block: Pointer)
    fun pbmx_block_builder(pbmx: Pointer): Pointer
    fun pbmx_build_block(pbmx: Pointer, builder: Pointer): Pointer
    fun pbmx_delete_block_builder(proof: Pointer)

    fun pbmx_publish_key_payload(builder: Pointer, name: String, key: Pointer): Int
    fun pbmx_open_stack_payload(builder: Pointer, stack: Array<RawMask>, len: Long): Int
    fun pbmx_mask_stack_payload(
        builder: Pointer,
        id: RawFingerprint.ByValue,
        stack: Array<RawMask>,
        len: Long,
        proofs: Array<Pointer>
    ): Int

    fun pbmx_shuffle_stack_payload(
        builder: Pointer,
        id: RawFingerprint.ByValue,
        stack: Array<RawMask>,
        len: Long,
        proof: Pointer
    ): Int

    fun pbmx_shift_stack_payload(
        builder: Pointer,
        id: RawFingerprint.ByValue,
        stack: Array<RawMask>,
        len: Long,
        proof: Pointer
    ): Int

    fun pbmx_name_stack_payload(builder: Pointer, id: RawFingerprint.ByValue, name: String): Int
    fun pbmx_take_stack_payload(
        builder: Pointer,
        id1: RawFingerprint.ByValue,
        indices: LongArray,
        len: Long,
        id2: RawFingerprint.ByValue
    ): Int

    fun pbmx_pile_stacks_payload(
        builder: Pointer,
        ids: Array<RawFingerprint>,
        len: Long,
        id: RawFingerprint.ByValue
    ): Int

    fun pbmx_publish_shares_payload(
        builder: Pointer,
        id: RawFingerprint.ByValue,
        shares: Array<RawShare>,
        len: Long,
        proofs: Array<Pointer>
    ): Int

    fun pbmx_random_spec_payload(builder: Pointer, name: String, spec: String): Int
    fun pbmx_random_entropy_payload(builder: Pointer, name: String, entropy: RawMask.ByValue): Int
    fun pbmx_random_reveal_payload(builder: Pointer, name: String, share: RawShare.ByValue, proof: Pointer): Int
    fun pbmx_prove_entanglement_payload(
        builder: Pointer,
        sources: Array<RawFingerprint>,
        len: Long,
        shuffles: Array<RawFingerprint>,
        proof: Pointer
    )

    fun pbmx_text_payload(builder: Pointer, text: String): Int
    fun pbmx_bytes_payload(builder: Pointer, buf: ByteBuffer, len: Long): Int

    fun pbmx_export_block(key: Pointer, buf: ByteBuffer?, len: LongByReference): Int
    fun pbmx_import_block(buf: ByteBuffer, len: Long): Pointer

    fun pbmx_stack_id(stack: Array<RawMask>, len: Long): RawFingerprint.ByValue

    fun pbmx_block_id(block: Pointer): RawFingerprint.ByValue
    fun pbmx_block_signer(block: Pointer): RawFingerprint.ByValue
    fun pbmx_block_validate(pbmx: Pointer, block: Pointer): Int

    fun pbmx_blocks(pbmx: Pointer, outBlocks: Array<Pointer>?, len: LongByReference): Int
    fun pbmx_roots(pbmx: Pointer, outIds: Array<RawFingerprint>?, len: LongByReference): Int
    fun pbmx_heads(pbmx: Pointer, outIds: Array<RawFingerprint>?, len: LongByReference): Int
    fun pbmx_merged_chain(pbmx: Pointer): Int
    fun pbmx_empty_chain(pbmx: Pointer): Int
    fun pbmx_incomplete_chain(pbmx: Pointer): Int
    fun pbmx_parent_ids(block: Pointer, outIds: Array<RawFingerprint>?, len: LongByReference): Int
    fun pbmx_payloads(block: Pointer, outPayloads: Array<Pointer>?, len: LongByReference): Int
    fun pbmx_payload_kind(payload: Pointer, outKind: IntByReference): Int

    fun pbmx_unwrap_publish_key(
        payload: Pointer,
        outName: ByteArray?,
        len: LongByReference,
        outKey: PointerByReference?
    ): Int

    fun pbmx_unwrap_open_stack(payload: Pointer, outMasks: Array<RawMask>?, len: LongByReference): Int
    fun pbmx_unwrap_mask_stack(
        payload: Pointer,
        outId: RawFingerprint?,
        outMasks: Array<RawMask>?,
        len: LongByReference,
        outProof: Array<Pointer>?
    ): Int

    fun pbmx_unwrap_shuffle_stack(
        payload: Pointer,
        outId: RawFingerprint?,
        outMasks: Array<RawMask>?,
        len: LongByReference,
        outProof: PointerByReference?
    ): Int

    fun pbmx_unwrap_shift_stack(
        payload: Pointer,
        outId: RawFingerprint?,
        outMasks: Array<RawMask>?,
        len: LongByReference,
        outProof: PointerByReference?
    ): Int

    fun pbmx_unwrap_name_stack(payload: Pointer, outId: RawFingerprint?, outName: ByteArray?, len: LongByReference): Int

    fun pbmx_unwrap_take_stack(
        payload: Pointer,
        outId1: RawFingerprint?,
        outIndices: LongArray?,
        len: LongByReference,
        outId2: RawFingerprint?
    ): Int

    fun pbmx_unwrap_pile_stacks(
        payload: Pointer,
        outIds: Array<RawFingerprint>?,
        len: LongByReference,
        outId: RawFingerprint?
    ): Int

    fun pbmx_unwrap_publish_shares(
        payload: Pointer,
        outId: RawFingerprint?,
        outShares: Array<RawShare>?,
        len: LongByReference,
        outProof: Array<Pointer>?
    ): Int

    fun pbmx_unwrap_random_spec(
        payload: Pointer,
        outName: ByteArray?,
        nameLen: LongByReference,
        outSpec: ByteArray?,
        SpecLen: LongByReference
    ): Int

    fun pbmx_unwrap_random_entropy(
        payload: Pointer,
        outName: ByteArray?,
        nameLen: LongByReference,
        outEntropy: RawMask?
    ): Int

    fun pbmx_unwrap_random_reveal(
        payload: Pointer,
        outName: ByteArray?,
        nameLen: LongByReference,
        outShare: RawShare?,
        outProof: PointerByReference?
    ): Int

    fun pbmx_unwrap_prove_entanglement(
        payload: Pointer,
        outSources: Array<RawFingerprint>?,
        len: LongByReference,
        outShuffles: Array<RawFingerprint>?,
        outProof: PointerByReference
    )

    fun pbmx_unwrap_text(payload: Pointer, outBuf: ByteArray?, len: LongByReference): Int

    fun pbmx_unwrap_bytes(payload: Pointer, outBuf: ByteArray?, len: LongByReference): Int

    fun pbmx_rngs(
        pbmx: Pointer,
        outNameIdx: LongArray?,
        len: LongByReference,
        outNames: ByteArray?,
        namesLen: LongByReference,
        outRngs: Array<Pointer>?
    ): Int

    fun pbmx_rng_spec(rng: Pointer, outName: ByteArray?, len: LongByReference): Int
    fun pbmx_rng_mask(rng: Pointer, outMask: RawMask): Int
    fun pbmx_rng_add_entropy(rng: Pointer, party: RawFingerprint.ByValue, mask: RawMask.ByValue): Int
    fun pbmx_rng_add_secret(rng: Pointer, party: RawFingerprint.ByValue, share: RawShare.ByValue): Int
    fun pbmx_rng_entropy_parties(rng: Pointer, outParties: Array<RawFingerprint>?, len: LongByReference): Int
    fun pbmx_rng_secret_parties(rng: Pointer, outParties: Array<RawFingerprint>?, len: LongByReference): Int
    fun pbmx_rng_generated(rng: Pointer): Int
    fun pbmx_rng_revealed(rng: Pointer): Int
    fun pbmx_rng_gen(pbmx: Pointer, rng: Pointer, outValue: LongByReference): Int
}

val FFI = Native.load("pbmx_ffi", LibPbmx::class.java) as LibPbmx
