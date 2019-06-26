package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Mask;
import java.util.Collection;
import java.util.ArrayList;

public final class MaskStackPayload extends Payload {
    public MaskStackPayload(Id stack, Collection<Mask> masked, Collection<Mask.Proof> proofs) {
        this.stack = stack;
        this.masked = new ArrayList(masked);
        this.proofs = new ArrayList(proofs);
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.maskStack(stack, masked, proofs);
    }

    private final Id stack;
    private final Collection<Mask> masked;
    private final Collection<Mask.Proof> proofs;
}
