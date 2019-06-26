package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.PublicKey;

public final class PublishKeyPayload extends Payload {
    public PublishKeyPayload(String name, PublicKey key) {
        this.name = name;
        this.key = key;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.publishKey(name, key);
    }

    private final String name;
    private final PublicKey key;
}
