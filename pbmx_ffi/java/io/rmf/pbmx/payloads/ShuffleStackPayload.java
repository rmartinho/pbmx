package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Mask;
import io.rmf.pbmx.ShuffleProof;
import java.util.Collection;
import java.util.ArrayList;

public final class ShuffleStackPayload extends Payload {
    public ShuffleStackPayload(Id stack, Collection<Mask> shuffleed, ShuffleProof proof) {
        this.stack = stack;
        this.shuffleed = new ArrayList(shuffleed);
        this.proof = proof;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.shuffleStack(stack, shuffleed, proof);
    }

    private final Id stack;
    private final Collection<Mask> shuffleed;
    private final ShuffleProof proof;
}
