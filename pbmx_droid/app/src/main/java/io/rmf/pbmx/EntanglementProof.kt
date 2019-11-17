package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI

class EntanglementProof internal constructor(internal var handle: Pointer) {

    protected fun finalize() {
        FFI.pbmx_delete_entanglement_proof(this.handle)
    }
}
