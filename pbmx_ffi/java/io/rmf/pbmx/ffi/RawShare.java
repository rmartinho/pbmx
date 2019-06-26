package io.rmf.pbmx.ffi;

import java.util.Arrays;
import java.util.List;
import com.sun.jna.Structure;

public class RawShare extends Structure {
    public static class ByValue extends RawShare implements Structure.ByValue {}

    public byte[] bytes = new byte[32];

    public ByValue val() {
        ByValue value = new ByValue();
        value.bytes = this.bytes;
        return value;
    }

    public RawShare ref() {
        RawShare s = new RawShare();
        s.bytes = this.bytes;
        return s;
    }

    protected List getFieldOrder() {
        return Arrays.asList(new String[] { "bytes" });
    }
}
