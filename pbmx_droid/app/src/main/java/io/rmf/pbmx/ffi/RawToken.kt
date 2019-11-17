package io.rmf.pbmx.ffi

import com.sun.jna.Structure

open class RawToken : Structure() {

    @JvmField var bytes = ByteArray(32)

    class ByValue : RawToken(), Structure.ByValue

    fun value(): ByValue {
        val value = ByValue()
        value.bytes = this.bytes
        return value
    }

    fun ref(): RawToken {
        val t = RawToken()
        t.bytes = this.bytes
        return t
    }

    override fun getFieldOrder(): List<String> {
        return listOf("bytes")
    }
}
