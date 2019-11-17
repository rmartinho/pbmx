package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import io.rmf.pbmx.PublicKey
import io.rmf.pbmx.ffi.FFI

class PublishKeyPayload(handle: Pointer) : Payload(handle) {
    val name: String
    val key: PublicKey

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_publish_key(this.handle, null, length, null)
        assert(r == 0)

        val outName = ByteArray(length.value.toInt())
        val outKey = PointerByReference()
        r = FFI.pbmx_unwrap_publish_key(this.handle, outName, length, outKey)
        assert(r != 0)
        this.name = outName.toString(Charsets.UTF_8)
        this.key = PublicKey(outKey.value)
    }
}
