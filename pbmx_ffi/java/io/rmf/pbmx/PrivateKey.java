package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawRng;
import java.lang.IllegalArgumentException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

public final class PrivateKey {
    PrivateKey(Pointer handle) {
        this.handle = handle;
    }

    public static PrivateKey random() {
        return PrivateKey.random(null);
    }

    public static PrivateKey random(Rng rng) {
        Pointer handle = LibPbmx.INSTANCE.pbmx_random_key(RawRng.wrap(rng));
        return new PrivateKey(handle);
    }

    public static PrivateKey readFrom(ByteBuffer buf) {
        Pointer handle = LibPbmx.INSTANCE.pbmx_import_private_key(buf, buf.remaining());
        return new PrivateKey(handle);
    }

    public void writeTo(WritableByteChannel channel) throws IOException {
        LongByReference len = new LongByReference();
        int r = LibPbmx.INSTANCE.pbmx_export_private_key(this.handle, null, len);
        assert r != 0;

        ByteBuffer buf = ByteBuffer.allocate((int)len.getValue());
        r = LibPbmx.INSTANCE.pbmx_export_private_key(this.handle, buf, len);
        assert r != 0;

        channel.write(buf);
    }

    public PublicKey publicKey() {
        return new PublicKey(this);
    }

    @Override
    public void finalize() {
        LibPbmx.INSTANCE.pbmx_delete_private_key(this.handle);
    }

    Pointer handle;
}
