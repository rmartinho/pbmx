package io.rmf.pbmx

import com.sun.jna.Pointer
import com.sun.jna.Structure
import io.rmf.pbmx.ffi.RawFingerprint
import io.rmf.pbmx.ffi.RawMask
import io.rmf.pbmx.ffi.RawScalar
import io.rmf.pbmx.ffi.RawShare

fun toMaskArray(masks: Collection<Mask>): Array<RawMask> {
    val array = jnaArrayOf(RawMask(), masks.size)
    masks.withIndex().forEach { (i, m) ->
        run {
            array[i].bytes0 = m.raw.bytes0
            array[i].bytes1 = m.raw.bytes1
        }
    }
    return array
}

fun toScalarArray(scalars: Collection<Scalar>): Array<RawScalar> {
    val array = jnaArrayOf(RawScalar(), scalars.size)
    scalars.withIndex().forEach { (i, m) ->
        run {
            array[i].bytes = m.raw.bytes
        }
    }
    return array
}

fun toShareArray(shares: Collection<Share>): Array<RawShare> {
    val array = jnaArrayOf(RawShare(), shares.size)
    shares.withIndex().forEach { (i, m) -> array[i].bytes = m.raw.bytes }
    return array
}

fun toIdArray(ids: Collection<Id>): Array<RawFingerprint> {
    val array = jnaArrayOf(RawFingerprint(), ids.size)
    ids.withIndex().forEach { (i, id) -> array[i].bytes = id.raw.bytes }
    return array
}

fun toMaskPointerArray(proofs: Collection<Mask.Proof>): Array<Pointer> {
    return proofs.map { it.handle }.toTypedArray()
}

fun toSharePointerArray(proofs: Collection<Share.Proof>): Array<Pointer> {
    return proofs.map { it.handle }.toTypedArray()
}

fun <T : Structure> jnaArrayOf(t: T, len: Int): Array<T> {
    @Suppress("UNCHECKED_CAST")
    return t.toArray(len) as Array<T>
}
