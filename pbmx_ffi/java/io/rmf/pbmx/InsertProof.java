package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import com.sun.jna.Pointer;

public final class InsertProof {
    InsertProof(Pointer handle) {
        this.handle = handle;
    }

    @Override
    protected void finalize() {
        LibPbmx.INSTANCE.pbmx_delete_insert_proof(this.handle);
    }

    Pointer handle;
}
