package io.rmf.pbmx

import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawXof
import java.nio.ByteBuffer

class Xof internal constructor(private var raw: RawXof) {

    fun read(buffer: ByteBuffer) {
        val r = FFI.pbmx_read_xof(this.raw.value(), buffer, buffer.remaining().toLong())
        assert(r != 0)
    }
}

