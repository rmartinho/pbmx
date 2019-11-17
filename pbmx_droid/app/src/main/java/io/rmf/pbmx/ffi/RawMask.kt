package io.rmf.pbmx.ffi

import com.sun.jna.Structure

open class RawMask : Structure() {

    @JvmField var bytes0 = ByteArray(32)
    @JvmField var bytes1 = ByteArray(32)

    class ByValue : RawMask(), Structure.ByValue

    fun value(): ByValue {
        val value = ByValue()
        value.bytes0 = this.bytes0
        value.bytes1 = this.bytes1
        return value
    }

    override fun getFieldOrder(): List<String> {
        return listOf("bytes0", "bytes1")
    }
}

