package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI

class PublicKey {

    internal var handle: Pointer

    internal constructor(handle: Pointer) {
        this.handle = handle
    }

    constructor(sk: PrivateKey) {
        this.handle = FFI.pbmx_public_key(sk.handle)
    }

    val fingerprint get() = Fingerprint(FFI.pbmx_key_fingerprint(this.handle))

    fun finalize() {
        FFI.pbmx_delete_public_key(this.handle)
    }
}
