package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI

class TextPayload(handle: Pointer) : Payload(handle) {
    val text: String

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_text(this.handle, null, length)
        assert(r == 0)

        val outBuf = ByteArray(length.value.toInt())
        r = FFI.pbmx_unwrap_bytes(this.handle, outBuf, length)
        assert(r != 0)
        this.text = outBuf.toString(Charsets.UTF_8)
    }
}
