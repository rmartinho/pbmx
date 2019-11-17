package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Mask
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawMask

class RandomEntropyPayload(handle: Pointer) : Payload(handle) {
    val name: String
    val entropy: Mask

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_random_entropy(this.handle, null, length, null)
        assert(r == 0)

        val outName = ByteArray(length.value.toInt())
        val outEntropy = RawMask()
        r = FFI.pbmx_unwrap_random_entropy(this.handle, outName, length, outEntropy)
        assert(r != 0)
        this.name = outName.toString(Charsets.UTF_8)
        this.entropy = Mask(outEntropy)
    }
}

