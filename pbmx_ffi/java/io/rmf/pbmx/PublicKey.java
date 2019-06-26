package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import com.sun.jna.Pointer;

public final class PublicKey {
    PublicKey(Pointer handle) {
        this.handle = handle;
    }

    public PublicKey(PrivateKey sk) {
        this.handle = LibPbmx.INSTANCE.pbmx_public_key(sk.handle);
    }

    public Fingerprint fingerprint() {
        return new Fingerprint(LibPbmx.INSTANCE.pbmx_key_fingerprint(this.handle));
    }

    @Override
    public void finalize() {
        LibPbmx.INSTANCE.pbmx_delete_public_key(this.handle);
    }

    Pointer handle;
}

