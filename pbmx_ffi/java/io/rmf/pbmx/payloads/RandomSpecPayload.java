package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;

public final class RandomSpecPayload extends Payload {
    public RandomSpecPayload(String name, String spec) {
        this.name = name;
        this.spec = spec;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.randomSpec(name, spec);
    }

    private final String name;
    private final String spec;
}

