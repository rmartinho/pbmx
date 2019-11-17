package io.rmf.pbmx

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.payloads.Payload
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel

class Block internal constructor(internal var handle: Pointer) {

    val id get() = Id(FFI.pbmx_block_id(this.handle))

    val signer get() = Fingerprint(FFI.pbmx_block_signer(this.handle))

    val payloads: List<Payload>
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_payloads(this.handle, null, length)
            assert(r == 0)

            val payloads = Array(length.value.toInt()) { Pointer.NULL }
            r = FFI.pbmx_payloads(this.handle, payloads, length)
            assert(r != 0)

            return payloads.map { Payload.from(it) }.toList()
        }

    @Throws(IOException::class)
    fun writeTo(channel: WritableByteChannel) {
        val len = LongByReference()
        var r = FFI.pbmx_export_block(this.handle, null, len)
        assert(r == 0)

        val buf = ByteBuffer.allocate(len.value.toInt())
        r = FFI.pbmx_export_block(this.handle, buf, len)
        assert(r != 0)

        channel.write(buf)
    }

    protected fun finalize() {
        FFI.pbmx_delete_block(this.handle)
    }

    companion object {

        fun readFrom(buf: ByteBuffer): Block {
            val handle = FFI.pbmx_import_block(buf, buf.remaining().toLong())
            return Block(handle)
        }
    }
}
