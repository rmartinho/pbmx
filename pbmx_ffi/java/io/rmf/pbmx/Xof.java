package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawXof;
import java.nio.ByteBuffer;

public final class Xof {
    RawXof raw;

    Xof(RawXof raw) {
        this.raw = raw;
    }

    public void read(ByteBuffer buffer) {
        int r = LibPbmx.INSTANCE.pbmx_read_xof(this.raw.val(), buffer, buffer.remaining());
        assert r != 0;
    }
}

