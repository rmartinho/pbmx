package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Mask;

public final class RandomEntropyPayload extends Payload {
    public RandomEntropyPayload(String name, Mask entropy) {
        this.name = name;
        this.entropy = entropy;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.randomEntropy(name, entropy);
    }

    private final String name;
    private final Mask entropy;
}

