package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Mask;
import java.util.Collection;
import java.util.ArrayList;

public final class OpenStackPayload extends Payload {
    public OpenStackPayload(Collection<Mask> stack) {
        this.stack = new ArrayList(stack);
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.openStack(stack);
    }

    private final Collection<Mask> stack;
}
