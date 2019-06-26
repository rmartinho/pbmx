package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Id;
import io.rmf.pbmx.Share;
import java.util.Collection;
import java.util.ArrayList;

public final class PublishSharesPayload extends Payload {
    public PublishSharesPayload(Id stack, Collection<Share> shares, Collection<Share.Proof> proofs) {
        this.stack = stack;
        this.shares = new ArrayList(shares);
        this.proofs = new ArrayList(proofs);
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.publishShares(stack, shares, proofs);
    }

    private final Id stack;
    private final Collection<Share> shares;
    private final Collection<Share.Proof> proofs;
}
