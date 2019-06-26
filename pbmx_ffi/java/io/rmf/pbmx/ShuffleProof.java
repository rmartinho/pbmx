package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import com.sun.jna.Pointer;

public final class ShuffleProof {
    ShuffleProof(Pointer handle) {
        this.handle = handle;
    }

    @Override
    protected void finalize() {
        LibPbmx.INSTANCE.pbmx_delete_shuffle_proof(this.handle);
    }

    Pointer handle;
}
