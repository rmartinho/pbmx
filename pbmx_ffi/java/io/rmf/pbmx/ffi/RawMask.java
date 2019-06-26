package io.rmf.pbmx.ffi;

import java.util.Arrays;
import java.util.List;
import com.sun.jna.Structure;

public class RawMask extends Structure {
    public static class ByValue extends RawMask implements Structure.ByValue {}

    public byte[] bytes0 = new byte[32];
    public byte[] bytes1 = new byte[32];

    public ByValue val() {
        ByValue value = new ByValue();
        value.bytes0 = this.bytes0;
        value.bytes1 = this.bytes1;
        return value;
    }

    public RawMask ref() {
        RawMask m = new RawMask();
        m.bytes0 = this.bytes0;
        m.bytes1 = this.bytes1;
        return m;
    }

    protected List getFieldOrder() {
        return Arrays.asList(new String[] { "bytes0", "bytes1" });
    }
}

