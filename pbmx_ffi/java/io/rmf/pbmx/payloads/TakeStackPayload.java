package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import java.util.Arrays;

public final class TakeStackPayload extends Payload {
    public TakeStackPayload(Id stack, long[] indices, Id taken) {
        this.stack = stack;
        this.indices = Arrays.copyOf(indices, indices.length);
        this.taken = taken;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.takeStack(stack, indices, taken);
    }

    private final Id stack;
    private final long[] indices;
    private final Id taken;
}

