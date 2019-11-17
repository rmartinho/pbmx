package io.rmf.pbmx

import com.sun.jna.Pointer
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawShare

class Share internal constructor(internal var raw: RawShare) {

    class Proof internal constructor(internal var handle: Pointer) {

        protected fun finalize() {
            FFI.pbmx_delete_share_proof(this.handle)
        }
    }
}
