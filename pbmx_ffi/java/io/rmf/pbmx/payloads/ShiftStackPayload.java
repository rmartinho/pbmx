package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Mask;
import io.rmf.pbmx.ShiftProof;
import java.util.Collection;
import java.util.ArrayList;

public final class ShiftStackPayload extends Payload {
    public ShiftStackPayload(Id stack, Collection<Mask> shifted, ShiftProof proof) {
        this.stack = stack;
        this.shifted = new ArrayList(shifted);
        this.proof = proof;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.shiftStack(stack, shifted, proof);
    }

    private final Id stack;
    private final Collection<Mask> shifted;
    private final ShiftProof proof;
}
