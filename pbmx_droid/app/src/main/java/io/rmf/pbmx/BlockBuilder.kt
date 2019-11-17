package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI
import java.nio.ByteBuffer

class BlockBuilder internal constructor(internal var pbmx: Pointer, internal var handle: Pointer) {
    private var deleted = false

    internal fun build(): Block {
        if (deleted) {
            throw IllegalArgumentException()
        }
        this.deleted = true
        return Block(FFI.pbmx_build_block(this.pbmx, this.handle))
    }

    fun publishKey(name: String, key: PublicKey) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_publish_key_payload(this.handle, name, key.handle)
        assert(r != 0)
    }

    fun openStack(stack: Collection<Mask>) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val masks = toMaskArray(stack)
        val r = FFI.pbmx_open_stack_payload(this.handle, masks, masks.size.toLong())
        assert(r != 0)
    }

    fun maskStack(id: Id, stack: Collection<Mask>, proofs: Collection<Mask.Proof>) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val masks = toMaskArray(stack)
        val proofPtrs = toMaskPointerArray(proofs)
        val r =
            FFI.pbmx_mask_stack_payload(this.handle, id.raw.value(), masks, masks.size.toLong(), proofPtrs)
        assert(r != 0)
    }

    fun shuffleStack(id: Id, stack: Collection<Mask>, proof: ShuffleProof) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val masks = toMaskArray(stack)
        val r =
            FFI.pbmx_shuffle_stack_payload(
                this.handle,
                id.raw.value(),
                masks,
                masks.size.toLong(),
                proof.handle
            )
        assert(r != 0)
    }

    fun shiftStack(id: Id, stack: Collection<Mask>, proof: ShiftProof) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val masks = toMaskArray(stack)
        val r = FFI.pbmx_shift_stack_payload(
            this.handle,
            id.raw.value(),
            masks,
            masks.size.toLong(),
            proof.handle
        )
        assert(r != 0)
    }

    fun nameStack(id: Id, name: String) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_name_stack_payload(this.handle, id.raw.value(), name)
        assert(r != 0)
    }

    fun takeStack(id1: Id, indices: LongArray, id2: Id) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_take_stack_payload(
            this.handle,
            id1.raw.value(),
            indices,
            indices.size.toLong(),
            id2.raw.value()
        )
        assert(r != 0)
    }

    fun pileStacks(ids: Collection<Id>, id: Id) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val fps = toIdArray(ids)
        val r = FFI.pbmx_pile_stacks_payload(this.handle, fps, fps.size.toLong(), id.raw.value())
        assert(r != 0)
    }

    fun publishShares(id: Id, shares: Collection<Share>, proofs: Collection<Share.Proof>) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val raws = toShareArray(shares)
        val proofPtrs = toSharePointerArray(proofs)
        val r = FFI.pbmx_publish_shares_payload(
            this.handle, id.raw.value(), raws,
            raws.size.toLong(), proofPtrs
        )
        assert(r != 0)
    }

    fun randomSpec(name: String, spec: String) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_random_spec_payload(this.handle, name, spec)
        assert(r != 0)
    }

    fun randomEntropy(name: String, entropy: Mask) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_random_entropy_payload(this.handle, name, entropy.raw.value())
        assert(r != 0)
    }

    fun randomReveal(name: String, share: Share, proof: Share.Proof) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_random_reveal_payload(this.handle, name, share.raw.value(), proof.handle)
        assert(r != 0)
    }

    fun text(str: String) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_text_payload(this.handle, str)
        assert(r != 0)
    }

    fun bytes(buf: ByteBuffer) {
        if (deleted) {
            throw IllegalArgumentException()
        }
        val r = FFI.pbmx_bytes_payload(this.handle, buf, buf.remaining().toLong())
        assert(r != 0)
    }

    protected fun finalize() {
        if (!deleted) {
            FFI.pbmx_delete_block_builder(this.handle)
        }
    }
}
