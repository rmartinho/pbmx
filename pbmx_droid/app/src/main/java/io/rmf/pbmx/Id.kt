package io.rmf.pbmx

import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint

class Id internal constructor(internal var raw: RawFingerprint): Comparable<Id> {

    override fun equals(other: Any?): Boolean {
        return this.toString() == other.toString()
    }

    override fun hashCode(): Int {
        return this.toString().hashCode()
    }

    override fun compareTo(other: Id): Int {
        return this.toString().compareTo(other.toString())
    }

    override fun toString(): String {
        return this.raw.bytes
            .fold(StringBuilder()) { sb, b -> sb.append(String.format("%02x", b)) }
            .toString()
    }

    companion object {

        fun of(stack: Collection<Mask>): Id {
            val masks = toMaskArray(stack)
            return Id(FFI.pbmx_stack_id(masks, masks.size.toLong()))
        }
    }
}

