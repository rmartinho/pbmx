package io.rmf.pbmx.ffi

import com.sun.jna.Structure

open class RawShare : Structure() {

    @JvmField var bytes = ByteArray(32)

    class ByValue : RawShare(), Structure.ByValue

    fun value(): ByValue {
        val value = ByValue()
        value.bytes = this.bytes
        return value
    }

    override fun getFieldOrder(): List<String> {
        return listOf("bytes")
    }
}
