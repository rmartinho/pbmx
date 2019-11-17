package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Id
import io.rmf.pbmx.Mask
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint
import io.rmf.pbmx.ffi.RawMask
import io.rmf.pbmx.jnaArrayOf

class MaskStackPayload(handle: Pointer) : Payload(handle) {
    val stack: Id
    val masked: Collection<Mask>
    val proofs: Collection<Mask.Proof>

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_mask_stack(this.handle, null, null, length, null)
        assert(r == 0)

        val outId = RawFingerprint()
        val outMasks = jnaArrayOf(RawMask(), length.value.toInt())
        val outProofs = Array(length.value.toInt()) { Pointer.NULL }
        r = FFI.pbmx_unwrap_mask_stack(this.handle, outId, outMasks, length, outProofs)
        assert(r != 0)
        this.stack = Id(outId)
        this.masked = outMasks.map { Mask(it) }.toList()
        this.proofs = outProofs.map { Mask.Proof(it) }.toList()
    }
}
