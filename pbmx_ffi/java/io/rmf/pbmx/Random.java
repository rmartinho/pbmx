package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawRng;
import com.sun.jna.ptr.LongByReference;

public final class Random {
    public static long[] permutation(int length) {
        return Random.doPermutation(length, null);
    }

    public static long[] permutation(int length, Rng rng) {
        return Random.doPermutation(length, RawRng.wrap(rng));
    }

    private static long[] doPermutation(int length, RawRng rng) {
        long[] p = new long[length];
        int r = LibPbmx.INSTANCE.pbmx_random_permutation(rng, length, p);
        assert r != 0;

        return p;
    }

    public static int shift(int length) {
        return Random.doShift(length, null);
    }

    public static int shift(int length, Rng rng) {
        return Random.doShift(length, RawRng.wrap(rng));
    }

    private static int doShift(int length, RawRng rng) {
        LongByReference outK = new LongByReference();
        int r = LibPbmx.INSTANCE.pbmx_random_shift(rng, length, outK);
        assert r != 0;

        return (int)outK.getValue();
    }
}
