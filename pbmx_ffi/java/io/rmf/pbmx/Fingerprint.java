package io.rmf.pbmx;

import io.rmf.pbmx.ffi.RawFingerprint;

public final class Fingerprint {
    RawFingerprint raw;

    Fingerprint(RawFingerprint raw) {
        this.raw = raw;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.raw.bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

