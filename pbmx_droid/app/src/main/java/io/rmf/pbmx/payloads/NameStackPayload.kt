package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Id
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint

class NameStackPayload(handle: Pointer) : Payload(handle) {
    val stack: Id
    val name: String

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_name_stack(this.handle, null, null, length)
        assert(r == 0)

        val outId = RawFingerprint()
        val outName = ByteArray(length.value.toInt())
        r = FFI.pbmx_unwrap_name_stack(this.handle, outId, outName, length)
        assert(r != 0)
        this.stack = Id(outId)
        this.name = outName.toString(Charsets.UTF_8)
    }
}