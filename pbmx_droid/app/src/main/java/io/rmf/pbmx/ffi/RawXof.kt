package io.rmf.pbmx.ffi

import com.sun.jna.Pointer
import com.sun.jna.Structure

open class RawXof : Structure() {

    @Suppress("MemberVisibilityCanBePrivate")
    lateinit var data: Pointer
    @Suppress("MemberVisibilityCanBePrivate")
    lateinit var vtable: Pointer

    class ByValue : Structure(), Structure.ByValue {
        lateinit var data: Pointer
        lateinit var vtable: Pointer

        override fun getFieldOrder(): List<String> {
            return listOf("data", "vtable")
        }
    }

    fun value(): ByValue {
        val value = ByValue()
        value.data = this.data
        value.vtable = this.vtable
        return value
    }

    override fun getFieldOrder(): List<String> {
        return listOf("data", "vtable")
    }

    protected fun finalize() {
        FFI.pbmx_delete_xof(this.value())
    }
}

