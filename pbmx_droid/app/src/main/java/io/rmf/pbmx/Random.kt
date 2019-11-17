package io.rmf.pbmx

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI

fun randomPermutation(length: Int): LongArray {
    val p = LongArray(length)
    val r = FFI.pbmx_random_permutation(Pointer.NULL, length.toLong(), p)
    assert(r != 0)

    return p
}

fun randomShift(length: Int): Int {
    val outK = LongByReference()
    val r = FFI.pbmx_random_shift(Pointer.NULL, length.toLong(), outK)
    assert(r != 0)

    return outK.value.toInt()
}
