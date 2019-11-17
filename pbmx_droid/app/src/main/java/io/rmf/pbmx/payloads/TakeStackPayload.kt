package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Id
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint

class TakeStackPayload(handle: Pointer) : Payload(handle) {
    val stack: Id
    val indices: LongArray
    val taken: Id

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_take_stack(this.handle, null, null, length, null)
        assert(r == 0)

        val outId1 = RawFingerprint()
        val outIndices = LongArray(length.value.toInt())
        val outId2 = RawFingerprint()
        r = FFI.pbmx_unwrap_take_stack(this.handle, outId1, outIndices, length, outId2)
        assert(r != 0)
        this.stack = Id(outId1)
        this.indices = outIndices
        this.taken = Id(outId2)
    }
}
