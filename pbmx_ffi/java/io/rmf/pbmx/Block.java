package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

public final class Block {
    Block(Pointer handle) {
        this.handle = handle;
    }

    public Id id() {
        return new Id(LibPbmx.INSTANCE.pbmx_block_id(this.handle));
    }

    public Fingerprint signer() {
        return new Fingerprint(LibPbmx.INSTANCE.pbmx_block_id(this.handle));
    }

    public static Block readFrom(ByteBuffer buf) {
        Pointer handle = LibPbmx.INSTANCE.pbmx_import_block(buf, buf.remaining());
        return new Block(handle);
    }

    public void writeTo(WritableByteChannel channel) throws IOException {
        LongByReference len = new LongByReference();
        int r = LibPbmx.INSTANCE.pbmx_export_block(this.handle, null, len);
        assert r != 0;

        ByteBuffer buf = ByteBuffer.allocate((int)len.getValue());
        r = LibPbmx.INSTANCE.pbmx_export_block(this.handle, buf, len);
        assert r != 0;

        channel.write(buf);
    }

    @Override
    protected void finalize() {
        LibPbmx.INSTANCE.pbmx_delete_block(this.handle);
    }

    Pointer handle;
}
