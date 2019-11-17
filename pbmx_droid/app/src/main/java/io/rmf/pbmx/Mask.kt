package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawMask

class Mask internal constructor(internal var raw: RawMask) {

    operator fun plus(other: Mask): Mask {
        val outMask = RawMask()
        val r = FFI.pbmx_add_masks(this.raw.value(), other.raw.value(), outMask)
        assert(r != 0)

        return Mask(outMask)
    }

    override fun equals(other: Any?): Boolean {
        if (other !is Mask) return false
        return this.raw.bytes0.contentEquals(other.raw.bytes0)
                && this.raw.bytes1.contentEquals(other.raw.bytes1)
    }

    override fun hashCode(): Int {
        return this.raw.bytes0.plus(this.raw.bytes1).hashCode()
    }

    class Proof internal constructor(internal var handle: Pointer) {

        protected fun finalize() {
            FFI.pbmx_delete_mask_proof(this.handle)
        }
    }
}
