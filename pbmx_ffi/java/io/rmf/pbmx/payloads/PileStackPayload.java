package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Mask;
import java.util.Collection;
import java.util.ArrayList;

public final class PileStackPayload extends Payload {
    public PileStackPayload(Collection<Id> stacks, Id pile) {
        this.stacks = new ArrayList(stacks);
        this.pile = pile;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.pileStacks(stacks, pile);
    }

    private final Collection<Id> stacks;
    private final Id pile;
}
