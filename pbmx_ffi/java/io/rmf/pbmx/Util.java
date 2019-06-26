package io.rmf.pbmx;

import io.rmf.pbmx.ffi.RawMask;
import io.rmf.pbmx.ffi.RawShare;
import io.rmf.pbmx.ffi.RawFingerprint;
import com.sun.jna.Pointer;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.Collectors;

class Util {
    static RawMask[] toMaskArray(Collection<Mask> masks) {
        RawMask[] array = (RawMask[]) new RawMask().toArray(masks.size());
        int i = 0;
        for(Mask m : masks) {
            array[i].bytes0 = m.raw.bytes0;
            array[i].bytes1 = m.raw.bytes1;
            ++i;
        }
        return array;
    }

    static RawShare[] toShareArray(Collection<Share> shares) {
        RawShare[] array = (RawShare[]) new RawShare().toArray(shares.size());
        int i = 0;
        for(Share m : shares) {
            array[i].bytes = m.raw.bytes;
            ++i;
        }
        return array;
    }

    static RawFingerprint[] toIdArray(Collection<Id> ids) {
        RawFingerprint[] array = (RawFingerprint[]) new RawFingerprint().toArray(ids.size());
        int i = 0;
        for(Id id : ids) {
            array[i].bytes = id.raw.bytes;
            ++i;
        }
        return array;
    }

    static List<Mask> fromMaskArray(RawMask[] raws) {
        return Stream.of(raws)
            .map(m -> new Mask(m))
            .collect(Collectors.toList());
    }

    static Pointer[] toMaskPointerArray(Collection<Mask.Proof> proofs) {
        Pointer[] array = new Pointer[proofs.size()];
        int i = 0;
        for(Mask.Proof p : proofs) {
            array[i] = p.handle;
            ++i;
        }
        return array;
    }

    static Pointer[] toSharePointerArray(Collection<Share.Proof> proofs) {
        Pointer[] array = new Pointer[proofs.size()];
        int i = 0;
        for(Share.Proof p : proofs) {
            array[i] = p.handle;
            ++i;
        }
        return array;
    }
}
