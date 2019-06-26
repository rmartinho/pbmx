package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Mask;
import io.rmf.pbmx.InsertProof;
import java.util.Collection;
import java.util.ArrayList;

public final class InsertStackPayload extends Payload {
    public InsertStackPayload(Id stack, Id needle, Collection<Mask> inserted, InsertProof proof) {
        this.stack = stack;
        this.needle = needle;
        this.inserted = new ArrayList(inserted);
        this.proof = proof;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.insertStack(stack, needle, inserted, proof);
    }

    private final Id stack;
    private final Id needle;
    private final Collection<Mask> inserted;
    private final InsertProof proof;
}
