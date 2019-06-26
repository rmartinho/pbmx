package io.rmf.pbmx.ffi;

import com.sun.jna.Structure;
import java.util.List;
import java.util.Arrays;

public class RawFingerprint extends Structure {
    public static class ByValue extends RawFingerprint implements Structure.ByValue {}

    public byte[] bytes = new byte[20];

    public ByValue val() {
        ByValue value = new ByValue();
        value.bytes = this.bytes;
        return value;
    }

    public RawFingerprint ref() {
        RawFingerprint s = new RawFingerprint();
        s.bytes = this.bytes;
        return s;
    }

    @Override
    protected List getFieldOrder() {
        return Arrays.asList(new String[] { "bytes" });
    }
}
