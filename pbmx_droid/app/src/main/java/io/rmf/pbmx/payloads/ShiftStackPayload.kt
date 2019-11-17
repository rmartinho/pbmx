package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import io.rmf.pbmx.Id
import io.rmf.pbmx.Mask
import io.rmf.pbmx.ShiftProof
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint
import io.rmf.pbmx.ffi.RawMask
import io.rmf.pbmx.jnaArrayOf

class ShiftStackPayload(handle: Pointer) : Payload(handle) {
    val stack: Id
    val shifted: Collection<Mask>
    val proof: ShiftProof

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_shift_stack(this.handle, null, null, length, null)
        assert(r == 0)

        val outId = RawFingerprint()
        val outMasks = jnaArrayOf(RawMask(), length.value.toInt())
        val outProof = PointerByReference()
        r = FFI.pbmx_unwrap_shift_stack(this.handle, outId, outMasks, length, outProof)
        assert(r != 0)
        this.stack = Id(outId)
        this.shifted = outMasks.map { Mask(it) }.toList()
        this.proof = ShiftProof(outProof.value)
    }
}
