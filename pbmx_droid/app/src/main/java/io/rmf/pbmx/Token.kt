package io.rmf.pbmx

import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawToken

class Token internal constructor(internal var raw: RawToken): Comparable<Token> {

    fun decode(): Long {
        val value = FFI.pbmx_decode_token(this.raw.value())
        assert(value != -1L)
        return value
    }

    override fun equals(other: Any?): Boolean {
        return this.decode() == (other as Token).decode()
    }

    override fun hashCode(): Int {
        return this.decode().hashCode()
    }

    override fun compareTo(other: Token): Int {
        return this.decode().compareTo(other.decode())
    }

    override fun toString(): String {
        return this.decode().toString()
    }

    companion object {

        fun encode(value: Long): Token {
            assert(value != -1L)
            return Token(FFI.pbmx_encode_token(value).ref())
        }
    }
}
