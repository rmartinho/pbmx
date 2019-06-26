package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawShare;
import com.sun.jna.Pointer;

public final class Share {
    RawShare raw;

    Share(RawShare raw) {
        this.raw = raw;
    }

    public static final class Proof {
        Proof(Pointer handle) {
            this.handle = handle;
        }

        @Override
        protected void finalize() {
            LibPbmx.INSTANCE.pbmx_delete_share_proof(this.handle);
        }

        Pointer handle;
    }
}
