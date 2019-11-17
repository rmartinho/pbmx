package io.rmf.pbmx

import io.rmf.pbmx.ffi.RawScalar

class Scalar internal constructor(internal var raw: RawScalar) {

    override fun equals(other: Any?): Boolean {
        if (other !is Scalar) return false
        return this.raw.bytes.contentEquals(other.raw.bytes)
    }

    override fun hashCode(): Int {
        return this.raw.bytes.hashCode()
    }
}
