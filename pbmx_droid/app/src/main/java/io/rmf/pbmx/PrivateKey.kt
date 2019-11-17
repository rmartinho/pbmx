package io.rmf.pbmx

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel

class PrivateKey internal constructor(internal var handle: Pointer) {

    @Throws(IOException::class)
    fun writeTo(channel: WritableByteChannel) {
        val len = LongByReference()
        len.value = 17
        var r = FFI.pbmx_export_private_key(this.handle, null, len)
        assert(r == 0)

        val buf = ByteBuffer.allocate(len.value.toInt())
        r = FFI.pbmx_export_private_key(this.handle, buf, len)
        assert(r != 0)

        channel.write(buf)
    }

    val publicKey get() = PublicKey(this)

    fun finalize() {
        FFI.pbmx_delete_private_key(this.handle)
    }

    companion object {

        fun random(): PrivateKey {
            val handle = FFI.pbmx_random_key(Pointer.NULL)
            return PrivateKey(handle)
        }

        fun readFrom(buf: ByteBuffer): PrivateKey {
            val handle = FFI.pbmx_import_private_key(buf, buf.remaining().toLong())
            return PrivateKey(handle)
        }
    }
}
