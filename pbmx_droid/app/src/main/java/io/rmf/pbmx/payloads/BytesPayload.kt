package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI

class BytesPayload(handle: Pointer) : Payload(handle) {
    val bytes: ByteArray

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_bytes(this.handle, null, length)
        assert(r == 0)

        this.bytes = ByteArray(length.value.toInt())
        r = FFI.pbmx_unwrap_bytes(this.handle, this.bytes, length)
        assert(r != 0)
    }
}
