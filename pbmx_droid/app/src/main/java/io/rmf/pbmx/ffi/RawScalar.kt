package io.rmf.pbmx.ffi

import com.sun.jna.Structure

open class RawScalar : Structure() {

    @JvmField
    var bytes = ByteArray(32)

    class ByValue : RawScalar(), Structure.ByValue

    fun value(): ByValue {
        val value = ByValue()
        value.bytes = this.bytes
        return value
    }

    override fun getFieldOrder(): List<String> {
        return listOf("bytes")
    }
}