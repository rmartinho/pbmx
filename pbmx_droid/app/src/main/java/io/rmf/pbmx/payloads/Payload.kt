package io.rmf.pbmx.payloads

import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import io.rmf.pbmx.ffi.FFI

abstract class Payload protected constructor(val handle: Pointer) {

    private enum class Kind(val code: Int) {
        PUBLISH_KEY(1) {
            override fun create(handle: Pointer): Payload {
                return PublishKeyPayload(handle)
            }
        },
        OPEN_STACK(2) {
            override fun create(handle: Pointer): Payload {
                return OpenStackPayload(handle)
            }
        },
        MASK_STACK(3) {
            override fun create(handle: Pointer): Payload {
                return MaskStackPayload(handle)
            }
        },
        SHUFFLE_STACK(4) {
            override fun create(handle: Pointer): Payload {
                return ShuffleStackPayload(handle)
            }
        },
        SHIFT_STACK(5) {
            override fun create(handle: Pointer): Payload {
                return ShiftStackPayload(handle)
            }
        },
        NAME_STACK(6) {
            override fun create(handle: Pointer): Payload {
                return NameStackPayload(handle)
            }
        },
        TAKE_STACK(7) {
            override fun create(handle: Pointer): Payload {
                return TakeStackPayload(handle)
            }
        },
        PILE_STACKS(8) {
            override fun create(handle: Pointer): Payload {
                return PileStacksPayload(handle)
            }
        },
        PUBLISH_SHARES(9) {
            override fun create(handle: Pointer): Payload {
                return PublishSharesPayload(handle)
            }
        },
        RANDOM_SPEC(10) {
            override fun create(handle: Pointer): Payload {
                return RandomSpecPayload(handle)
            }
        },
        RANDOM_ENTROPY(11) {
            override fun create(handle: Pointer): Payload {
                return RandomEntropyPayload(handle)
            }
        },
        RANDOM_REVEAL(12) {
            override fun create(handle: Pointer): Payload {
                return RandomRevealPayload(handle)
            }
        },
        PROVE_ENTANGLEMENT(13) {
            override fun create(handle: Pointer): Payload {
                return BytesPayload(handle)
            }
        },
        TEXT(14) {
            override fun create(handle: Pointer): Payload {
                return TextPayload(handle)
            }
        },
        BYTES(15) {
            override fun create(handle: Pointer): Payload {
                return BytesPayload(handle)
            }
        };

        abstract fun create(handle: Pointer): Payload
    }

    companion object {
        internal fun from(handle: Pointer): Payload {
            val outKind = IntByReference()
            val r = FFI.pbmx_payload_kind(handle, outKind)
            assert(r != 0)

            val kind = Kind.values().single { it.code == outKind.value }
            return kind.create(handle)
        }
    }
}
