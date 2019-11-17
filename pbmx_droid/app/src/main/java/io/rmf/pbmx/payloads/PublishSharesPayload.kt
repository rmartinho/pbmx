package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Id
import io.rmf.pbmx.Share
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint
import io.rmf.pbmx.ffi.RawShare
import io.rmf.pbmx.jnaArrayOf

class PublishSharesPayload(handle: Pointer) : Payload(handle) {
    val stack: Id
    val shares: Collection<Share>
    val proofs: Collection<Share.Proof>

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_publish_shares(this.handle, null, null, length, null)
        assert(r == 0)

        val outId = RawFingerprint()
        val outShares = jnaArrayOf(RawShare(), length.value.toInt())
        val outProofs = Array(length.value.toInt()) { Pointer.NULL }
        r = FFI.pbmx_unwrap_publish_shares(this.handle, outId, outShares, length, outProofs)
        assert(r != 0)
        this.stack = Id(outId)
        this.shares = outShares.map { Share(it) }.toList()
        this.proofs = outProofs.map { Share.Proof(it) }.toList()
    }
}
