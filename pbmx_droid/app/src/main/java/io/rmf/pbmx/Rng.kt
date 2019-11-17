package io.rmf.pbmx

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import io.rmf.pbmx.ffi.FFI
import io.rmf.pbmx.ffi.RawFingerprint
import io.rmf.pbmx.ffi.RawMask

class Rng internal constructor(internal var handle: Pointer) {

    val spec: String
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_rng_spec(this.handle, null, length)
            assert(r == 0)

            val outName = ByteArray(length.value.toInt())
            r = FFI.pbmx_rng_spec(this.handle, outName, length)
            assert(r != 0)
            return outName.toString(Charsets.UTF_8)
        }

    val mask: Mask
        get() {
            val raw = RawMask()
            val r = FFI.pbmx_rng_mask(this.handle, raw)
            assert(r != 0)
            return Mask(raw)
        }

    fun addEntropy(party: Fingerprint, entropy: Mask) {
        val r = FFI.pbmx_rng_add_entropy(this.handle, party.raw.value(), entropy.raw.value())
        assert(r != 0)
    }

    fun addSecret(party: Fingerprint, share: Share) {
        val r = FFI.pbmx_rng_add_secret(this.handle, party.raw.value(), share.raw.value())
        assert(r != 0)
    }

    val entropyParties: List<Fingerprint>
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_rng_entropy_parties(this.handle, null, length)
            assert(r == 0)

            val fps = jnaArrayOf(RawFingerprint(), length.value.toInt())
            r = FFI.pbmx_rng_entropy_parties(this.handle, fps, length)
            assert(r != 0)

            return fps.map { Fingerprint(it) }.toList()
        }

    val secretParties: List<Fingerprint>
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_rng_secret_parties(this.handle, null, length)
            assert(r == 0)

            val fps = jnaArrayOf(RawFingerprint(), length.value.toInt())
            r = FFI.pbmx_rng_secret_parties(this.handle, fps, length)
            assert(r != 0)

            return fps.map { Fingerprint(it) }.toList()
        }

    val generated = FFI.pbmx_rng_generated(this.handle) != 0
    val revealed = FFI.pbmx_rng_revealed(this.handle) != 0
}