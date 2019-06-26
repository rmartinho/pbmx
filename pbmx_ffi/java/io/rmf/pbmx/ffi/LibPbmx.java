package io.rmf.pbmx.ffi;

import java.nio.ByteBuffer;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

public interface LibPbmx extends Library {
    public static LibPbmx INSTANCE = (LibPbmx)Native.load("pbmx_ffi", LibPbmx.class);

    Pointer pbmx_new(Pointer key);
    void pbmx_delete(Pointer key);

    Pointer pbmx_random_key(RawRng rng);
    void pbmx_delete_private_key(Pointer key);
    Pointer pbmx_public_key(Pointer key);
    void pbmx_delete_public_key(Pointer key);
    RawFingerprint.ByValue pbmx_key_fingerprint(Pointer key);
    int pbmx_export_private_key(Pointer key, ByteBuffer buf, LongByReference len);
    Pointer pbmx_import_private_key(ByteBuffer buf, long len);

    Pointer pbmx_private_key(Pointer pbmx);
    Pointer pbmx_shared_key(Pointer pbmx);
    void pbmx_add_key(Pointer pbmx, Pointer key);
    long pbmx_parties(Pointer pbmx, RawFingerprint[] buf, LongByReference len);

    RawToken.ByValue pbmx_encode_token(long value);
    long pbmx_decode_token(RawToken.ByValue token);

    int pbmx_mask(Pointer pbmx, RawToken.ByValue token, RawMask outMask, PointerByReference outProof);
    int pbmx_verify_mask(Pointer pbmx, RawToken.ByValue token, RawMask.ByValue mask, Pointer proof);
    void pbmx_delete_mask_proof(Pointer proof);

    int pbmx_remask(Pointer pbmx, RawMask.ByValue mask, RawMask outRemask, PointerByReference outProof);
    int pbmx_verify_remask(Pointer pbmx, RawMask.ByValue mask, RawMask.ByValue remask, Pointer proof);

    int pbmx_share(Pointer pbmx, RawMask.ByValue mask, RawShare outShare, PointerByReference outProof);
    int pbmx_verify_share(Pointer pbmx, RawFingerprint.ByValue fp, RawMask.ByValue mask, RawShare.ByValue share, Pointer proof);
    void pbmx_delete_share_proof(Pointer proof);

    int pbmx_unmask(Pointer pbmx, RawMask.ByValue mask, RawShare.ByValue share, RawMask outMask);
    int pbmx_unmask_private(Pointer pbmx, RawMask.ByValue mask, RawMask outMask);
    int pbmx_unmask_open(Pointer pbmx, RawMask.ByValue mask, RawToken outToken);

    int pbmx_shuffle(Pointer pbmx, RawMask[] stack, long len, long[] perm, RawMask[] outShuffle, PointerByReference outProof);
    int pbmx_verify_shuffle(Pointer pbmx, RawMask[] stack, long len, RawMask[] shuffle, Pointer proof);
    void pbmx_delete_shuffle_proof(Pointer proof);

    int pbmx_shift(Pointer pbmx, RawMask[] stack, long len, long k, RawMask[] outShift, PointerByReference outProof);
    int pbmx_verify_shift(Pointer pbmx, RawMask[] stack, long len, RawMask[] shift, Pointer proof);
    void pbmx_delete_shift_proof(Pointer proof);

    int pbmx_insert(Pointer pbmx, RawMask[] stack, long lenStack, RawMask[] needle, long lenNeedle, long k, RawMask[] outInserted, PointerByReference outProof);
    int pbmx_verify_insert(Pointer pbmx, RawMask[] stack, long lenStack, RawMask[] needle, long lenNeedle, RawMask[] inserted, Pointer proof);
    void pbmx_delete_insert_proof(Pointer proof);

    int pbmx_random_permutation(RawRng rng, long len, long[] outPerm);
    int pbmx_random_shift(RawRng rng, long len, LongByReference outK);

    int pbmx_mask_random(Pointer pbmx, RawRng rng, RawMask outMask);
    int pbmx_unmask_random(Pointer pbmx, RawMask.ByValue mask, RawXof outXof);

    int pbmx_read_xof(RawXof.ByValue xof, ByteBuffer buf, long len);
    void pbmx_delete_xof(RawXof.ByValue xof);

    int pbmx_add_block(Pointer pbmx, Pointer block);
    void pbmx_delete_block(Pointer block);
    Pointer pbmx_block_builder(Pointer pbmx);
    Pointer pbmx_build_block(Pointer pbmx, Pointer builder);
    void pbmx_delete_block_builder(Pointer proof);

    int pbmx_publish_key_payload(Pointer builder, String name, Pointer key);
    int pbmx_open_stack_payload(Pointer builder, RawMask[] stack, long len);
    int pbmx_mask_stack_payload(Pointer builder, RawFingerprint.ByValue id, RawMask[] stack, long len, Pointer[] proofs);
    int pbmx_shuffle_stack_payload(Pointer builder, RawFingerprint.ByValue id, RawMask[] stack, long len, Pointer proof);
    int pbmx_shift_stack_payload(Pointer builder, RawFingerprint.ByValue id, RawMask[] stack, long len, Pointer proof);
    int pbmx_name_stack_payload(Pointer builder, RawFingerprint.ByValue id, String name);
    int pbmx_take_stack_payload(Pointer builder, RawFingerprint.ByValue id1, long[] indices, long len, RawFingerprint.ByValue id2);
    int pbmx_pile_stacks_payload(Pointer builder, RawFingerprint[] ids, long len, RawFingerprint.ByValue id);
    int pbmx_insert_stack_payload(Pointer builder, RawFingerprint.ByValue id1, RawFingerprint.ByValue id2, RawMask[] masks, long len, Pointer proof);
    int pbmx_publish_shares_payload(Pointer builder, RawFingerprint.ByValue id, RawShare[] shares, long len, Pointer[] proofs);
    int pbmx_random_spec_payload(Pointer builder, String name, String spec);
    int pbmx_random_entropy_payload(Pointer builder, String name, RawMask.ByValue entropy);
    int pbmx_random_reveal_payload(Pointer builder, String name, RawShare.ByValue share, Pointer proof);
    int pbmx_bytes_payload(Pointer builder, ByteBuffer buf, long len);

    int pbmx_export_block(Pointer key, ByteBuffer buf, LongByReference len);
    Pointer pbmx_import_block(ByteBuffer buf, long len);

    RawFingerprint.ByValue pbmx_stack_id(RawMask[] stack, long len);

    RawFingerprint.ByValue pbmx_block_id(Pointer block);
    RawFingerprint.ByValue pbmx_block_signer(Pointer block);
    int pbmx_block_validate(Pointer pbmx, Pointer block);
}
