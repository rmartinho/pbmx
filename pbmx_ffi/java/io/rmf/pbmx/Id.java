package io.rmf.pbmx;

import static io.rmf.pbmx.Util.toMaskArray;
import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawMask;
import io.rmf.pbmx.ffi.RawFingerprint;
import java.util.Collection;

public final class Id {
    RawFingerprint raw;

    Id(RawFingerprint raw) {
        this.raw = raw;
    }

    public static Id of(Collection<Mask> stack) {
        RawMask[] masks = toMaskArray(stack);
        return new Id(LibPbmx.INSTANCE.pbmx_stack_id(masks, masks.length));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.raw.bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

