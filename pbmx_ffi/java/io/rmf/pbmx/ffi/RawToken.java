package io.rmf.pbmx.ffi;

import java.util.Arrays;
import java.util.List;
import com.sun.jna.Structure;

public class RawToken extends Structure {
    public static class ByValue extends RawToken implements Structure.ByValue {}

    public byte[] bytes = new byte[32];

    public ByValue val() {
        ByValue value = new ByValue();
        value.bytes = this.bytes;
        return value;
    }

    public RawToken ref() {
        RawToken t = new RawToken();
        t.bytes = this.bytes;
        return t;
    }

    protected List getFieldOrder() {
        return Arrays.asList(new String[] { "bytes" });
    }
}
