// int pbmx_publish_key_payload(Pointer builder, String name, Pointer key);
// int pbmx_open_stack_payload(Pointer builder, RawMask[] stack, long len);
// int pbmx_mask_stack_payload(Pointer builder, RawFingerprint.ByValue id, RawMask[] stack, long len, Pointer[] proofs);
// int pbmx_shuffle_stack_payload(Pointer builder, RawFingerprint.ByValue id, RawMask[] stack, long len, Pointer proof);
// int pbmx_shift_stack_payload(Pointer builder, RawFingerprint.ByValue id, RawMask[] stack, long len, Pointer proof);
// int pbmx_name_stack_payload(Pointer builder, RawFingerprint.ByValue id, String name);
// int pbmx_take_stack_payload(Pointer builder, RawFingerprint.ByValue id1, long[] indices, long len, RawFingerprint.ByValue id2);
// int pbmx_pile_stacks_payload(Pointer builder, RawFingerprint[] ids, long len, RawFingerprint.ByValue id);
// int pbmx_insert_stack_payload(Pointer builder, RawFingerprint.ByValue id1, RawFingerprint.ByValue id2, RawMask[] masks, long len, Pointer proof);
// int pbmx_publish_shares_payload(Pointer builder, RawFingerprint.ByValue id, RawShare[] shares, long len, Pointer[] proofs);
// int pbmx_random_spec_payload(Pointer builder, String name, String spec);
// int pbmx_random_entropy_payload(Pointer builder, String name, RawMask entropy);
// int pbmx_random_reveal_payload(Pointer builder, String name, RawShare share, Pointer proof);
// int pbmx_bytes_payload(Pointer builder, ByteBuffer buf, long len);

package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;

public abstract class Payload {
    public abstract void addTo(BlockBuilder builder);
}
