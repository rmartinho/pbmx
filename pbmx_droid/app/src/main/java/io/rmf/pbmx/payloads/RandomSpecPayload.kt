package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI

class RandomSpecPayload(handle: Pointer) : Payload(handle) {
    val name: String
    val spec: String

    init {
        val nameLength = LongByReference()
        val specLength = LongByReference()
        var r = FFI.pbmx_unwrap_random_spec(this.handle, null, nameLength, null, specLength)
        assert(r == 0)

        val outName = ByteArray(nameLength.value.toInt())
        val outSpec = ByteArray(nameLength.value.toInt())
        r = FFI.pbmx_unwrap_random_spec(this.handle, outName, nameLength, outSpec, specLength)
        assert(r != 0)
        this.name = outName.toString(Charsets.UTF_8)
        this.spec = outSpec.toString(Charsets.UTF_8)
    }
}

