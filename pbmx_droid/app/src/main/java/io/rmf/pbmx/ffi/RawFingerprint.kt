package io.rmf.pbmx.ffi

import com.sun.jna.Structure

open class RawFingerprint : Structure() {

    @JvmField var bytes = ByteArray(20)

    class ByValue : RawFingerprint(), Structure.ByValue

    fun value(): ByValue {
        val value = ByValue()
        value.bytes = this.bytes
        return value
    }

    override fun getFieldOrder(): List<String> {
        return listOf("bytes")
    }
}
