package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;

public final class NameStackPayload extends Payload {
    public NameStackPayload(Id stack, String name) {
        this.stack = stack;
        this.name = name;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.nameStack(stack, name);
    }

    private final Id stack;
    private final String name;
}


