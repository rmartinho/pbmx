package io.rmf.pbmx;

import static io.rmf.pbmx.Util.toMaskArray;
import static io.rmf.pbmx.Util.fromMaskArray;
import io.rmf.pbmx.ffi.LibPbmx;
import io.rmf.pbmx.ffi.RawToken;
import io.rmf.pbmx.ffi.RawMask;
import io.rmf.pbmx.ffi.RawShare;
import io.rmf.pbmx.ffi.RawFingerprint;
import io.rmf.pbmx.ffi.RawRng;
import io.rmf.pbmx.ffi.RawXof;
import java.lang.IllegalArgumentException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

public final class Pbmx {
    public Pbmx(PrivateKey sk) {
        this.handle = LibPbmx.INSTANCE.pbmx_new(sk.handle);
    }

    public PrivateKey privateKey() {
        Pointer handle = LibPbmx.INSTANCE.pbmx_private_key(this.handle);
        return new PrivateKey(handle);
    }
    public PublicKey sharedKey() {
        Pointer handle = LibPbmx.INSTANCE.pbmx_shared_key(this.handle);
        return new PublicKey(handle);
    }

    public void addKey(PublicKey pk) {
        LibPbmx.INSTANCE.pbmx_add_key(this.handle, pk.handle);
    }

    public List<Fingerprint> parties() {
        LongByReference length = new LongByReference();
        LibPbmx.INSTANCE.pbmx_parties(this.handle, null, length);

        RawFingerprint[] raws = (RawFingerprint[]) new RawFingerprint().toArray((int)length.getValue());
        LibPbmx.INSTANCE.pbmx_parties(this.handle, raws, length);

        return Stream.of(raws).map(r -> new Fingerprint(r)).collect(Collectors.toList());
    }

    public static final class MaskResult {
        public Mask mask;
        public Mask.Proof proof;
    }

    public MaskResult mask(Token token) {
        RawMask outMask = new RawMask();
        PointerByReference outProofPtr = new PointerByReference();
        int r = LibPbmx.INSTANCE.pbmx_mask(this.handle, token.raw.val(), outMask, outProofPtr);
        assert r != 0;

        MaskResult result = new MaskResult();
        result.mask = new Mask(outMask);
        result.proof = new Mask.Proof(outProofPtr.getValue());

        return result;
    }

    public boolean verifyMask(Token token, Mask mask, Mask.Proof proof) {
        return LibPbmx.INSTANCE.pbmx_verify_mask(this.handle, token.raw.val(), mask.raw.val(), proof.handle) != 0;
    }

    public MaskResult mask(Mask mask) {
        RawMask outRemask = new RawMask();
        PointerByReference outProofPtr = new PointerByReference();
        int r = LibPbmx.INSTANCE.pbmx_remask(this.handle, mask.raw.val(), outRemask, outProofPtr);
        assert r != 0;

        MaskResult result = new MaskResult();
        result.mask = new Mask(outRemask);
        result.proof = new Mask.Proof(outProofPtr.getValue());

        return result;
    }

    public boolean verifyMask(Mask mask, Mask remask, Mask.Proof proof) {
        return LibPbmx.INSTANCE.pbmx_verify_remask(this.handle, mask.raw.val(), remask.raw.val(), proof.handle) != 0;
    }

    public static final class ShareResult {
        public Share share;
        public Share.Proof proof;
    }

    public ShareResult share(Mask mask) {
        RawShare outShare = new RawShare();
        PointerByReference outProofPtr = new PointerByReference();
        int r = LibPbmx.INSTANCE.pbmx_share(this.handle, mask.raw.val(), outShare, outProofPtr);
        assert r != 0;

        ShareResult result = new ShareResult();
        result.share = new Share(outShare);
        result.proof = new Share.Proof(outProofPtr.getValue());

        return result;
    }

    public boolean verifyShare(Fingerprint fp, Mask mask, Share share, Share.Proof proof) {
        return LibPbmx.INSTANCE.pbmx_verify_share(this.handle, fp.raw.val(), mask.raw.val(), share.raw.val(), proof.handle) != 0;
    }

    public Mask unmaskShare(Mask mask, Share share) {
        RawMask outMask = new RawMask();
        int r = LibPbmx.INSTANCE.pbmx_unmask(this.handle, mask.raw.val(), share.raw.val(), outMask);
        assert r != 0;

        return new Mask(outMask);
    }

    public Mask unmaskPrivate(Mask mask) {
        RawMask outMask = new RawMask();
        int r = LibPbmx.INSTANCE.pbmx_unmask_private(this.handle, mask.raw.val(), outMask);
        assert r != 0;

        return new Mask(outMask);
    }

    public Token unmaskOpen(Mask mask) {
        RawToken outToken = new RawToken();
        int r = LibPbmx.INSTANCE.pbmx_unmask_open(this.handle, mask.raw.val(), outToken);
        assert r != 0;

        return new Token(outToken);
    }

    public static final class ShuffleResult {
        List<Mask> shuffle;
        ShuffleProof proof;
    }

    public ShuffleResult shuffle(Collection<Mask> stack) {
        long[] p = Random.permutation(stack.size());
        return this.shuffle(stack, p);
    }

    public ShuffleResult shuffle(Collection<Mask> stack, long[] permutation) {
        RawMask[] masks = toMaskArray(stack);
        RawMask[] outShuffle = new RawMask[stack.size()];
        PointerByReference outProofPtr = new PointerByReference();
        int r = LibPbmx.INSTANCE.pbmx_shuffle(this.handle, masks, masks.length, permutation, outShuffle, outProofPtr);
        assert r != 0;

        ShuffleResult result = new ShuffleResult();
        result.shuffle = fromMaskArray(outShuffle);
        result.proof = new ShuffleProof(outProofPtr.getValue());
        return result;
    }

    public boolean verifyShuffle(Collection<Mask> stack, Collection<Mask> shuffle, ShuffleProof proof) {
        RawMask[] masks = toMaskArray(stack);
        RawMask[] shuffleMasks = toMaskArray(shuffle);
        return LibPbmx.INSTANCE.pbmx_verify_shuffle(this.handle, masks, masks.length, shuffleMasks, proof.handle) != 0;
    }

    public static final class ShiftResult {
        List<Mask> shift;
        ShiftProof proof;
    }

    public ShiftResult shift(Collection<Mask> stack) {
        int k = Random.shift(stack.size());
        return this.shift(stack, k);
    }

    public ShiftResult shift(Collection<Mask> stack, int k) {
        RawMask[] masks = toMaskArray(stack);
        RawMask[] outShift = new RawMask[stack.size()];
        PointerByReference outProofPtr = new PointerByReference();
        int r = LibPbmx.INSTANCE.pbmx_shift(this.handle, masks, masks.length, k, outShift, outProofPtr);
        assert r != 0;

        ShiftResult result = new ShiftResult();
        result.shift = fromMaskArray(outShift);
        result.proof = new ShiftProof(outProofPtr.getValue());
        return result;
    }

    public boolean verifyShift(Collection<Mask> stack, Collection<Mask> shift, ShiftProof proof) {
        RawMask[] masks = toMaskArray(stack);
        RawMask[] shiftMasks = toMaskArray(shift);
        return LibPbmx.INSTANCE.pbmx_verify_shift(this.handle, masks, masks.length, shiftMasks, proof.handle) != 0;
    }

    public static final class InsertResult {
        List<Mask> inserted;
        InsertProof proof;
    }


    public InsertResult insert(Collection<Mask> stack, Collection<Mask> needle) {
        int k = Random.shift(stack.size());
        return this.insert(stack, needle, k);
    }

    public InsertResult insert(Collection<Mask> stack, Collection<Mask> needle, int k) {
        RawMask[] masks = toMaskArray(stack);
        RawMask[] needleMasks = toMaskArray(needle);
        RawMask[] outInsert = new RawMask[stack.size() + needle.size()];
        PointerByReference outProofPtr = new PointerByReference();
        int r = LibPbmx.INSTANCE.pbmx_insert(this.handle, masks, masks.length, needleMasks, needleMasks.length, k, outInsert, outProofPtr);
        assert r != 0;

        InsertResult result = new InsertResult();
        result.inserted = fromMaskArray(outInsert);
        result.proof = new InsertProof(outProofPtr.getValue());
        return result;
    }

    public boolean verifyShift(Collection<Mask> stack, Collection<Mask> needle, Collection<Mask> inserted, ShiftProof proof) {
        RawMask[] masks = toMaskArray(stack);
        RawMask[] needleMasks = toMaskArray(needle);
        RawMask[] insertedMasks = toMaskArray(inserted);
        return LibPbmx.INSTANCE.pbmx_verify_insert(this.handle, masks, masks.length, needleMasks, needleMasks.length, insertedMasks, proof.handle) != 0;
    }

    public Mask maskRandom() {
        return this.maskRandom(null);
    }

    public Mask maskRandom(Rng rng) {
        RawMask outMask = new RawMask();
        int r = LibPbmx.INSTANCE.pbmx_mask_random(this.handle, RawRng.wrap(rng), outMask);
        assert r != 0;

        return new Mask(outMask);
    }

    public Xof unmaskRandom(Mask mask) {
        RawXof outXof = new RawXof();
        int r = LibPbmx.INSTANCE.pbmx_unmask_random(this.handle, mask.raw.val(), outXof);
        assert r != 0;

        return new Xof(outXof);
    }

    public void addBlock(Block block) {
        if(LibPbmx.INSTANCE.pbmx_block_validate(this.handle, block.handle) == 0) {
            throw new IllegalArgumentException();
        }
        int r = LibPbmx.INSTANCE.pbmx_add_block(this.handle, block.handle);
        assert r != 0;
    }

    public static interface BlockFn {
        void build(BlockBuilder builder);
    }

    public Block buildBlock(BlockFn fn) {
        BlockBuilder builder = new BlockBuilder(this.handle, LibPbmx.INSTANCE.pbmx_block_builder(this.handle));
        fn.build(builder);
        return builder.build();
    }

    @Override
    public void finalize() {
        LibPbmx.INSTANCE.pbmx_delete(this.handle);
    }

    Pointer handle;

    public static void main(String[] args) throws Exception {
        PrivateKey sk1 = PrivateKey.random();
        PrivateKey sk2 = PrivateKey.random();
        Pbmx pbmx1 = new Pbmx(sk1);
        pbmx1.addKey(sk2.publicKey());
        Pbmx pbmx2 = new Pbmx(sk2);
        pbmx2.addKey(sk1.publicKey());
        Fingerprint fp1 = sk1.publicKey().fingerprint();
        Fingerprint fp2 = sk2.publicKey().fingerprint();

        pbmx1.parties().forEach(fp -> System.out.println(fp));
        pbmx2.parties().forEach(fp -> System.out.println(fp));

        Long[] values = new Long[] { 1L, 2L, 3L };
        List<Token> tokens = Stream.of(values)
            .map(v -> Token.encode(v))
            .collect(Collectors.toList());
        List<Mask> masks1 = new ArrayList<Mask>();
        List<Mask.Proof> proofs = new ArrayList<Mask.Proof>();
        tokens.stream()
            .map(t -> pbmx1.mask(t))
            .forEach(r -> {
                masks1.add(r.mask);
                proofs.add(r.proof);
            });

        System.out.println("---");
        for(int i = 0; i < masks1.size(); ++i) {
            System.out.println(pbmx2.verifyMask(tokens.get(i), masks1.get(i), proofs.get(i)));
        }

        List<Mask> masks2 = new ArrayList<Mask>();
        List<Mask.Proof> reproofs = new ArrayList<Mask.Proof>();
        masks1.stream()
            .map(m -> pbmx2.mask(m))
            .forEach(r -> {
                masks2.add(r.mask);
                reproofs.add(r.proof);
            });

        System.out.println("---");
        for(int i = 0; i < masks2.size(); ++i) {
            System.out.println(pbmx1.verifyMask(masks1.get(i), masks2.get(i), reproofs.get(i)));
        }

        {
            List<Share> shares1 = new ArrayList<Share>();
            List<Share.Proof> proofs1 = new ArrayList<Share.Proof>();
            masks2.stream()
                .map(m -> pbmx1.share(m))
                .forEach(r -> {
                    shares1.add(r.share);
                    proofs1.add(r.proof);
                });

            System.out.println("---");
            for(int i = 0; i < masks2.size(); ++i) {
                System.out.println(pbmx2.verifyShare(fp1, masks2.get(i), shares1.get(i), proofs1.get(i)));
            }

            List<Share> shares2 = new ArrayList<Share>();
            List<Share.Proof> proofs2 = new ArrayList<Share.Proof>();
            masks2.stream()
                .map(m -> pbmx2.share(m))
                .forEach(r -> {
                    shares2.add(r.share);
                    proofs2.add(r.proof);
                });

            System.out.println("---");
            for(int i = 0; i < masks2.size(); ++i) {
                System.out.println(pbmx1.verifyShare(fp2, masks2.get(i), shares2.get(i), proofs2.get(i)));
            }

            System.out.println("---");
            for(int i = 0; i < masks2.size(); ++i) {
                Mask m0 = pbmx1.unmaskShare(masks2.get(i), shares2.get(i));
                Mask m1 = pbmx1.unmaskPrivate(m0);
                Token t0 = pbmx1.unmaskOpen(m1);
                System.out.println(t0.decode());
            }

            System.out.println("---");
            for(int i = 0; i < masks2.size(); ++i) {
                Mask m0 = pbmx2.unmaskShare(masks2.get(i), shares1.get(i));
                Mask m1 = pbmx2.unmaskPrivate(m0);
                Token t0 = pbmx2.unmaskOpen(m1);
                System.out.println(t0.decode());
            }
        }

        System.out.println("---");
        ShuffleResult shuffle1 = pbmx1.shuffle(masks2);
        System.out.println(pbmx2.verifyShuffle(masks2, shuffle1.shuffle, shuffle1.proof));
        ShuffleResult shuffle2 = pbmx2.shuffle(shuffle1.shuffle);
        System.out.println(pbmx1.verifyShuffle(shuffle1.shuffle, shuffle2.shuffle, shuffle2.proof));

        {
            List<Share> shares1 = new ArrayList<Share>();
            List<Share.Proof> proofs1 = new ArrayList<Share.Proof>();
            shuffle2.shuffle.stream()
                .map(m -> pbmx1.share(m))
                .forEach(r -> {
                    shares1.add(r.share);
                    proofs1.add(r.proof);
                });

            System.out.println("---");
            for(int i = 0; i < shuffle2.shuffle.size(); ++i) {
                System.out.println(pbmx2.verifyShare(fp1, shuffle2.shuffle.get(i), shares1.get(i), proofs1.get(i)));
            }

            List<Share> shares2 = new ArrayList<Share>();
            List<Share.Proof> proofs2 = new ArrayList<Share.Proof>();
            shuffle2.shuffle.stream()
                .map(m -> pbmx2.share(m))
                .forEach(r -> {
                    shares2.add(r.share);
                    proofs2.add(r.proof);
                });

            System.out.println("---");
            for(int i = 0; i < shuffle2.shuffle.size(); ++i) {
                System.out.println(pbmx1.verifyShare(fp2, shuffle2.shuffle.get(i), shares2.get(i), proofs2.get(i)));
            }

            System.out.println("---");
            for(int i = 0; i < shuffle2.shuffle.size(); ++i) {
                Mask m0 = pbmx1.unmaskShare(shuffle2.shuffle.get(i), shares2.get(i));
                Mask m1 = pbmx1.unmaskPrivate(m0);
                Token t0 = pbmx1.unmaskOpen(m1);
                System.out.println(t0.decode());
            }

            System.out.println("---");
            for(int i = 0; i < shuffle2.shuffle.size(); ++i) {
                Mask m0 = pbmx2.unmaskShare(shuffle2.shuffle.get(i), shares1.get(i));
                Mask m1 = pbmx2.unmaskPrivate(m0);
                Token t0 = pbmx2.unmaskOpen(m1);
                System.out.println(t0.decode());
            }
        }
    }
}
