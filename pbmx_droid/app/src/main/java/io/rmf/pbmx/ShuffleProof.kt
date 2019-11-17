package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI

class ShuffleProof internal constructor(internal var handle: Pointer) {

    protected fun finalize() {
        FFI.pbmx_delete_shuffle_proof(this.handle)
    }
}
