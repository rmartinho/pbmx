package io.rmf.pbmx;

import java.nio.ByteBuffer;

public interface Rng {
    int nextU32();
    long nextU64();
    void fillBytes(ByteBuffer buffer);
    boolean tryFillBytes(ByteBuffer buffer);
}
