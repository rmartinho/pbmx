package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Mask
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawMask
import io.rmf.pbmx.jnaArrayOf

class OpenStackPayload(handle: Pointer) : Payload(handle) {
    val stack: Collection<Mask>

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_open_stack(this.handle, null, length)
        assert(r == 0)

        val outMasks = jnaArrayOf(RawMask(), length.value.toInt())
        r = FFI.pbmx_unwrap_open_stack(this.handle, outMasks, length)
        assert(r != 0)
        this.stack = outMasks.map { Mask(it) }.toList()
    }
}
