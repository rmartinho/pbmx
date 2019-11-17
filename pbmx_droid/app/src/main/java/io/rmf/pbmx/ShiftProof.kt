package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI

class ShiftProof internal constructor(internal var handle: Pointer) {

    protected fun finalize() {
        FFI.pbmx_delete_shift_proof(this.handle)
    }
}
