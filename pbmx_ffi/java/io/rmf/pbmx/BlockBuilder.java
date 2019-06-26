package io.rmf.pbmx;

import static io.rmf.pbmx.Util.toMaskArray;
import static io.rmf.pbmx.Util.toShareArray;
import static io.rmf.pbmx.Util.toIdArray;
import static io.rmf.pbmx.Util.toMaskPointerArray;
import static io.rmf.pbmx.Util.toSharePointerArray;
import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawMask;
import io.rmf.pbmx.ffi.RawShare;
import io.rmf.pbmx.ffi.RawFingerprint;
import io.rmf.pbmx.payloads.Payload;
import java.util.Collection;
import java.nio.ByteBuffer;
import com.sun.jna.Pointer;

public final class BlockBuilder {
    BlockBuilder(Pointer pbmx, Pointer handle) {
        this.pbmx = pbmx;
        this.handle = handle;
    }

    Block build() {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        this.deleted = true;
        return new Block(LibPbmx.INSTANCE.pbmx_build_block(this.pbmx, this.handle));
    }

    public void add(Payload payload) {
        payload.addTo(this);
    }

    public void publishKey(String name, PublicKey key) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_publish_key_payload(this.handle, name, key.handle);
        assert r != 0;
    }

    public void openStack(Collection<Mask> stack) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawMask[] masks = toMaskArray(stack);
        int r = LibPbmx.INSTANCE.pbmx_open_stack_payload(this.handle, masks, masks.length);
        assert r != 0;
    }

    public void maskStack(Id id, Collection<Mask> stack, Collection<Mask.Proof> proofs) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawMask[] masks = toMaskArray(stack);
        Pointer[] proofPtrs = toMaskPointerArray(proofs);
        int r = LibPbmx.INSTANCE.pbmx_mask_stack_payload(this.handle, id.raw.val(), masks, masks.length, proofPtrs);
        assert r != 0;
    }

    public void shuffleStack(Id id, Collection<Mask> stack, ShuffleProof proof) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawMask[] masks = toMaskArray(stack);
        int r = LibPbmx.INSTANCE.pbmx_shuffle_stack_payload(this.handle, id.raw.val(), masks, masks.length, proof.handle);
        assert r != 0;
    }

    public void shiftStack(Id id, Collection<Mask> stack, ShiftProof proof) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawMask[] masks = toMaskArray(stack);
        int r = LibPbmx.INSTANCE.pbmx_shift_stack_payload(this.handle, id.raw.val(), masks, masks.length, proof.handle);
        assert r != 0;
    }

    public void nameStack(Id id, String name) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_name_stack_payload(this.handle, id.raw.val(), name);
        assert r != 0;
    }

    public void takeStack(Id id1, long[] indices, Id id2) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_take_stack_payload(this.handle, id1.raw.val(), indices, indices.length, id2.raw.val());
        assert r != 0;
    }

    public void pileStacks(Collection<Id> ids, Id id) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawFingerprint[] fps = toIdArray(ids);
        int r = LibPbmx.INSTANCE.pbmx_pile_stacks_payload(this.handle, fps, fps.length, id.raw.val());
        assert r != 0;
    }

    public void insertStack(Id id1, Id id2, Collection<Mask> stack, InsertProof proof) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawMask[] masks = toMaskArray(stack);
        int r = LibPbmx.INSTANCE.pbmx_insert_stack_payload(this.handle, id1.raw.val(), id2.raw.val(), masks, masks.length, proof.handle);
        assert r != 0;
    }

    public void publishShares(Id id, Collection<Share> shares, Collection<Share.Proof> proofs) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        RawShare[] raws = toShareArray(shares);
        Pointer[] proofPtrs = toSharePointerArray(proofs);
        int r = LibPbmx.INSTANCE.pbmx_publish_shares_payload(this.handle, id.raw.val(), raws, raws.length, proofPtrs);
        assert r != 0;
    }

    public void randomSpec(String name, String spec) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_random_spec_payload(this.handle, name, spec);
        assert r != 0;
    }

    public void randomEntropy(String name, Mask entropy) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_random_entropy_payload(this.handle, name, entropy.raw.val());
        assert r != 0;
    }

    public void randomReveal(String name, Share share, Share.Proof proof) {
        if(deleted) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_random_reveal_payload(this.handle, name, share.raw.val(), proof.handle);
        assert r != 0;
    }

    public void bytes(ByteBuffer buf) {
        int r = LibPbmx.INSTANCE.pbmx_bytes_payload(this.handle, buf, buf.remaining());
        assert r != 0;
    }

    @Override
    protected void finalize() {
        if(!deleted) {
            LibPbmx.INSTANCE.pbmx_delete_block_builder(this.handle);
        }
    }

    Pointer pbmx;
    Pointer handle;
    boolean deleted = false;
}
