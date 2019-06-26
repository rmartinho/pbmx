package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawMask;
import com.sun.jna.Pointer;

public final class Mask {
    RawMask raw;

    Mask(RawMask raw) {
        this.raw = raw;
    }

    public static final class Proof {
        Proof(Pointer handle) {
            this.handle = handle;
        }

        @Override
        protected void finalize() {
            LibPbmx.INSTANCE.pbmx_delete_mask_proof(this.handle);
        }

        Pointer handle;
    }
}
