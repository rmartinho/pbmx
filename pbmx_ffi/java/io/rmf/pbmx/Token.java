package io.rmf.pbmx;

import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawToken;

public final class Token {
    RawToken raw;

    Token(RawToken raw) {
        this.raw = raw;
    }

    public long decode() {
        long value = LibPbmx.INSTANCE.pbmx_decode_token(this.raw.val());
        assert value != -1;
        return value;
    }

    public static Token encode(long value) {
        assert value != -1;
        return new Token(LibPbmx.INSTANCE.pbmx_encode_token(value).ref());
    }
}
