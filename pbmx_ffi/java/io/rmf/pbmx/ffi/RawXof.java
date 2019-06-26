package io.rmf.pbmx.ffi;

import java.util.Arrays;
import java.util.List;
import com.sun.jna.Structure;
import com.sun.jna.Pointer;

public class RawXof extends Structure {
    public static class ByValue extends RawXof implements Structure.ByValue {}

    public Pointer data;
    public Pointer vtable;

    public ByValue val() {
        ByValue value = new ByValue();
        value.data = this.data;
        value.vtable = this.vtable;
        return value;
    }

    public RawXof ref() {
        RawXof x = new RawXof();
        x.data = this.data;
        x.vtable = this.vtable;
        return x;
    }

    @Override
    protected List getFieldOrder() {
        return Arrays.asList(new String[] { "data", "vtable" });
    }

    @Override
    protected void finalize() {
        LibPbmx.INSTANCE.pbmx_delete_xof(this.val());
    }
}

