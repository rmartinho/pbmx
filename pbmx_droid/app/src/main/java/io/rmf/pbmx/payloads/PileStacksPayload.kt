package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.Id
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint
import io.rmf.pbmx.jnaArrayOf

class PileStacksPayload(handle: Pointer) : Payload(handle) {
    val stacks: Collection<Id>
    val pile: Id

    init {
        val length = LongByReference()
        var r = FFI.pbmx_unwrap_pile_stacks(this.handle, null, length, null)
        assert(r == 0)

        val outIds = jnaArrayOf(RawFingerprint(), length.value.toInt())
        val outId = RawFingerprint()
        r = FFI.pbmx_unwrap_pile_stacks(this.handle, outIds, length, outId)
        assert(r != 0)
        this.stacks = outIds.map { Id(it) }.toList()
        this.pile = Id(outId)
    }
}
