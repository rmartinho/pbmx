package io.rmf.pbmx

import io.rmf.pbmx.ffi.RawFingerprint

class Fingerprint internal constructor(internal var raw: RawFingerprint): Comparable<Fingerprint> {

    override fun equals(other: Any?): Boolean {
        return this.toString() == other.toString()
    }

    override fun hashCode(): Int {
        return this.toString().hashCode()
    }

    override fun compareTo(other: Fingerprint): Int {
        return this.toString().compareTo(other.toString())
    }

    override fun toString(): String {
        return this.raw.bytes
            .fold(StringBuilder()) { sb, b -> sb.append(String.format("%02x", b)) }
            .toString()
    }
}

