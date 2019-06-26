package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import java.nio.ByteBuffer;

public final class BytesPayload extends Payload {
    public BytesPayload(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        ByteBuffer buf = ByteBuffer.wrap(this.bytes);
        builder.bytes(buf);
    }

    private final byte[] bytes;
}

