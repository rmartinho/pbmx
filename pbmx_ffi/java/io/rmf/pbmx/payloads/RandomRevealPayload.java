package io.rmf.pbmx.payloads;

import io.rmf.pbmx.BlockBuilder;
import io.rmf.pbmx.Share;

public final class RandomRevealPayload extends Payload {
    public RandomRevealPayload(String name, Share share, Share.Proof proof) {
        this.name = name;
        this.share = share;
        this.proof = proof;
    }

    @Override
    public void addTo(BlockBuilder builder) {
        builder.randomReveal(name, share, proof);
    }

    private final String name;
    private final Share share;
    private final Share.Proof proof;
}
