package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import io.rmf.pbmx.Share
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawShare

class RandomRevealPayload(handle: Pointer) : Payload(handle) {
    val name: String
    val share: Share
    val proof: Share.Proof

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_random_reveal(this.handle, null, length, null, null)
        assert(r == 0)

        val outName = ByteArray(length.value.toInt())
        val outShare = RawShare()
        val outProof = PointerByReference()
        r = FFI.pbmx_unwrap_random_reveal(this.handle, outName, length, outShare, outProof)
        assert(r != 0)
        this.name = outName.toString(Charsets.UTF_8)
        this.share = Share(outShare)
        this.proof = Share.Proof(outProof.value)
    }
}
