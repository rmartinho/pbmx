package io.rmf.pbmx.ffi;

import io.rmf.pbmx.Rng;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import com.sun.jna.Callback;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class RawRng extends Structure {
    public static interface NextU32Func extends Callback {
        int invoke(Structure data);
    }
    public static interface NextU64Func extends Callback {
        long invoke(Structure data);
    }
    public static interface FillBytesFunc extends Callback {
        void invoke(Structure data, Pointer buf, long len);
    }
    public static interface TryFillBytesFunc extends Callback {
        boolean invoke(Structure data, Pointer buf, long len);
    }

    public Structure.ByReference data;
    public NextU32Func nextU32;
    public NextU64Func nextU64;
    public FillBytesFunc fillBytes;
    public TryFillBytesFunc tryFillBytes;

    public static RawRng wrap(Rng rng) {
        if(rng == null) {
            return null;
        }
        RawRng f = new RawRng();
        f.data = (Structure.ByReference)rng;
        f.nextU32 = data -> {
            Rng r = (Rng)data;
            return r.nextU32();
        };
        f.nextU64 = data -> {
            Rng r = (Rng)data;
            return r.nextU64();
        };
        f.fillBytes = (data, pointer, len) -> {
            Rng r = (Rng)data;
            ByteBuffer buf = pointer.getByteBuffer(0, len);
            r.fillBytes(buf);
        };
        f.tryFillBytes = (data, pointer, len) -> {
            Rng r = (Rng)data;
            ByteBuffer buf = pointer.getByteBuffer(0, len);
            return r.tryFillBytes(buf);
        };
        return f;
    }

    protected List getFieldOrder() {
        return Arrays.asList(new String[] {
            "data",
            "nextU32",
            "nextU64",
            "fillBytes",
            "tryFillBytes"
        });
    }
}
