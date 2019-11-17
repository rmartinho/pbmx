package io.rmf.pbmx

import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import io.rmf.pbmx.ffi.*

class Pbmx(sk: PrivateKey) {

    internal var handle: Pointer = FFI.pbmx_new(sk.handle)

    private val privateKey get() = PrivateKey(FFI.pbmx_private_key(this.handle))

    val publicKey get() = this.privateKey.publicKey

    val sharedKey get() = PublicKey(FFI.pbmx_shared_key(this.handle))

    fun addKey(pk: PublicKey) {
        FFI.pbmx_add_key(this.handle, pk.handle)
    }

    val parties: Map<Fingerprint, String>
        get() {
            val length = LongByReference()
            val namesLength = LongByReference()
            var r = FFI.pbmx_parties(this.handle, null, length, null, null, namesLength)
            assert(r == 0)

            val fps = jnaArrayOf(RawFingerprint(), length.value.toInt())
            val names = ByteArray(namesLength.value.toInt())
            val indices = LongArray(length.value.toInt() + 1)
            r = FFI.pbmx_parties(this.handle, fps, length, indices, names, namesLength)
            assert(r != 0)
            indices[indices.size - 1] = names.size.toLong()
            val offsets = indices.fold(ArrayList<Pair<Int, Int>>()) { l, i ->
                if (i > 0) {
                    val begin = if (l.size > 0) l.last().second else 0
                    l.add(Pair(begin, i.toInt()))
                }
                l
            }
            val strings = offsets.map { String(names, it.first, it.second - it.first) }.toList()

            return fps.map { Fingerprint(it) }.zip(strings).toMap()
        }

    data class MaskResult(val mask: Mask, val proof: Mask.Proof)

    fun mask(token: Token): MaskResult {
        val outMask = RawMask()
        val outProofPtr = PointerByReference()
        val r = FFI.pbmx_mask(this.handle, token.raw.value(), outMask, outProofPtr)
        assert(r != 0)

        return MaskResult(Mask(outMask), Mask.Proof(outProofPtr.value))
    }

    fun verifyMask(token: Token, mask: Mask, proof: Mask.Proof): Boolean {
        return FFI.pbmx_verify_mask(this.handle, token.raw.value(), mask.raw.value(), proof.handle) != 0
    }

    fun mask(mask: Mask): MaskResult {
        val outRemask = RawMask()
        val outProofPtr = PointerByReference()
        val r = FFI.pbmx_remask(this.handle, mask.raw.value(), outRemask, outProofPtr)
        assert(r != 0)

        return MaskResult(Mask(outRemask), Mask.Proof(outProofPtr.value))
    }

    fun verifyMask(mask: Mask, remask: Mask, proof: Mask.Proof): Boolean {
        return FFI.pbmx_verify_remask(this.handle, mask.raw.value(), remask.raw.value(), proof.handle) != 0
    }

    data class ShareResult(val share: Share, val proof: Share.Proof)

    fun share(mask: Mask): ShareResult {
        val outShare = RawShare()
        val outProofPtr = PointerByReference()
        val r = FFI.pbmx_share(this.handle, mask.raw.value(), outShare, outProofPtr)
        assert(r != 0)

        return ShareResult(Share(outShare), Share.Proof(outProofPtr.value))
    }

    fun verifyShare(fp: Fingerprint, mask: Mask, share: Share, proof: Share.Proof): Boolean {
        return FFI.pbmx_verify_share(
            this.handle,
            fp.raw.value(),
            mask.raw.value(),
            share.raw.value(),
            proof.handle
        ) != 0
    }

    fun unmaskShare(mask: Mask, share: Share): Mask {
        val outMask = RawMask()
        val r = FFI.pbmx_unmask(this.handle, mask.raw.value(), share.raw.value(), outMask)
        assert(r != 0)

        return Mask(outMask)
    }

    fun unmaskPrivate(mask: Mask): Mask {
        val outMask = RawMask()
        val r = FFI.pbmx_unmask_private(this.handle, mask.raw.value(), outMask)
        assert(r != 0)

        return Mask(outMask)
    }

    fun unmaskOpen(mask: Mask): Token {
        val outToken = RawToken()
        val r = FFI.pbmx_unmask_open(this.handle, mask.raw.value(), outToken)
        assert(r != 0)

        return Token(outToken)
    }

    fun unmaskFull(mask: Mask, vararg share: Share): Token {
        val unmasked = share.fold(this.unmaskPrivate(mask)) { m: Mask, s: Share ->
            this.unmaskShare(m, s)
        }
        return this.unmaskOpen(unmasked)
    }

    data class ShuffleResult(val shuffle: List<Mask>, val secrets: List<Scalar>, val proof: ShuffleProof)

    fun shuffle(stack: Collection<Mask>): ShuffleResult {
        return this.shuffle(stack, randomPermutation(stack.size))
    }

    fun shuffle(stack: Collection<Mask>, permutation: LongArray): ShuffleResult {
        val masks = toMaskArray(stack)
        val outShuffle = jnaArrayOf(RawMask(), stack.size)
        val outSecrets = jnaArrayOf(RawScalar(), stack.size)
        val outProofPtr = PointerByReference()
        val r = FFI.pbmx_shuffle(
            this.handle, masks, masks.size.toLong(), permutation, outShuffle, outSecrets, outProofPtr
        )
        assert(r != 0)

        return ShuffleResult(
            outShuffle.map { Mask(it) }.toList(),
            outSecrets.map { Scalar(it) }.toList(),
            ShuffleProof(outProofPtr.value)
        )
    }

    fun verifyShuffle(stack: Collection<Mask>, shuffle: Collection<Mask>, proof: ShuffleProof): Boolean {
        val masks = toMaskArray(stack)
        val shuffleMasks = toMaskArray(shuffle)
        return FFI.pbmx_verify_shuffle(
            this.handle,
            masks,
            masks.size.toLong(),
            shuffleMasks,
            proof.handle
        ) != 0
    }

    data class ShiftResult(val shift: List<Mask>, val secrets: List<Scalar>, val proof: ShiftProof)

    fun shift(stack: Collection<Mask>): ShiftResult {
        val k = randomShift(stack.size)
        return this.shift(stack, k)
    }

    fun shift(stack: Collection<Mask>, k: Int): ShiftResult {
        val masks = toMaskArray(stack)
        val outShift = jnaArrayOf(RawMask(), stack.size)
        val outSecrets = jnaArrayOf(RawScalar(), stack.size)
        val outProofPtr = PointerByReference()
        val r = FFI.pbmx_shift(this.handle, masks, masks.size.toLong(), k.toLong(), outShift, outSecrets, outProofPtr)
        assert(r != 0)

        return ShiftResult(
            outShift.map { Mask(it) }.toList(),
            outSecrets.map { Scalar(it) }.toList(),
            ShiftProof(outProofPtr.value)
        )
    }

    fun verifyShift(stack: Collection<Mask>, shift: Collection<Mask>, proof: ShiftProof): Boolean {
        val masks = toMaskArray(stack)
        val shiftMasks = toMaskArray(shift)
        return FFI.pbmx_verify_shift(
            this.handle,
            masks,
            masks.size.toLong(),
            shiftMasks,
            proof.handle
        ) != 0
    }

    fun maskRandom(): Mask {
        val outMask = RawMask()
        val r = FFI.pbmx_mask_random(this.handle, Pointer.NULL, outMask)
        assert(r != 0)

        return Mask(outMask)
    }

    fun unmaskRandom(mask: Mask): Xof {
        val outXof = RawXof()
        val r = FFI.pbmx_unmask_random(this.handle, mask.raw.value(), outXof)
        assert(r != 0)

        return Xof(outXof)
    }

    fun unmaskRandom(mask: Mask, vararg share: Share): Xof {
        val unmasked = share.fold(this.unmaskPrivate(mask)) { m: Mask, s: Share ->
            this.unmaskShare(m, s)
        }
        return this.unmaskRandom(unmasked)
    }

    fun proveEntanglement(
        sources: Collection<Collection<Mask>>,
        shuffles: Collection<Collection<Mask>>,
        permutation: LongArray,
        secrets: Collection<Collection<Scalar>>
    ): EntanglementProof {
        val sourcesArray = toMaskArray(sources.flatten())
        val shufflesArray = toMaskArray(shuffles.flatten())
        val secretsArray = toScalarArray(secrets.flatten())

        val outProofPtr = PointerByReference()
        val r = FFI.pbmx_prove_entanglement(
            this.handle,
            sourcesArray,
            sources.size.toLong(),
            sources.first().size.toLong(),
            shufflesArray,
            permutation,
            secretsArray,
            outProofPtr
        )
        assert(r != 0)
        return EntanglementProof(outProofPtr.value)
    }

    fun verifyEntanglement(
        sources: Collection<Collection<Mask>>,
        shuffles: Collection<Collection<Mask>>,
        proof: EntanglementProof
    ): Boolean {
        val sourcesArray = toMaskArray(sources.flatten())
        val shufflesArray = toMaskArray(shuffles.flatten())

        return FFI.pbmx_verify_entanglement(
            this.handle,
            sourcesArray,
            sources.size.toLong(),
            sources.first().size.toLong(),
            shufflesArray,
            proof.handle
        ) != 0
    }

    fun addBlock(block: Block) {
        val r = FFI.pbmx_add_block(this.handle, block.handle)
        assert(r != 0)
    }

    fun addBlock(f: (BlockBuilder) -> Unit): Block {
        val block = this.buildBlock(f)
        this.addBlock(block)
        return block
    }

    fun buildBlock(f: (BlockBuilder) -> Unit): Block {
        val builder = BlockBuilder(this.handle, FFI.pbmx_block_builder(this.handle))
        f(builder)
        return builder.build()
    }

    fun validateBlock(block: Block): Boolean {
        return FFI.pbmx_block_validate(this.handle, block.handle) != 0
    }

    val blocks: List<Block>
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_blocks(this.handle, null, length)
            assert(r == 0)

            val ptrs = Array(length.value.toInt()) { Pointer.NULL }
            r = FFI.pbmx_blocks(this.handle, ptrs, length)
            assert(r != 0)

            return ptrs.map { Block(it!!) }.toList()
        }

    val heads: Iterable<Block>
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_heads(this.handle, null, length)
            assert(r == 0)

            val fps = jnaArrayOf(RawFingerprint(), length.value.toInt())
            r = FFI.pbmx_heads(this.handle, fps, length)
            assert(r != 0)
            val fpSet = fps.map { Id(it) }.toSortedSet()

            return this.blocks.filter { fpSet.contains(it.id) }
        }

    val roots: Iterable<Block>
        get() {
            val length = LongByReference()
            var r = FFI.pbmx_roots(this.handle, null, length)
            assert(r == 0)

            val fps = jnaArrayOf(RawFingerprint(), length.value.toInt())
            r = FFI.pbmx_roots(this.handle, fps, length)
            assert(r != 0)
            val fpSet = fps.map { Id(it) }.toSortedSet()

            return this.blocks.filter { fpSet.contains(it.id) }
        }

    val merged get() = FFI.pbmx_merged_chain(this.handle) != 0
    val empty get() = FFI.pbmx_empty_chain(this.handle) != 0
    val incomplete get() = FFI.pbmx_incomplete_chain(this.handle) != 0

    fun parentsOf(block: Block): Iterable<Block> {
        val length = LongByReference()
        var r = FFI.pbmx_parent_ids(block.handle, null, length)
        assert(r == 0)

        val fps = jnaArrayOf(RawFingerprint(), length.value.toInt())
        r = FFI.pbmx_parent_ids(block.handle, fps, length)
        assert(r != 0)
        val fpSet = fps.map { Id(it) }.toSortedSet()

        return this.blocks.filter { fpSet.contains(it.id) }
    }

    val rngs: Map<String, Rng>
        get() {
            val length = LongByReference()
            val namesLength = LongByReference()
            var r = FFI.pbmx_rngs(this.handle, null, length, null, namesLength, null)
            assert(r == 0)

            val rngs = Array(length.value.toInt()) { Pointer.NULL }
            val names = ByteArray(namesLength.value.toInt())
            val indices = LongArray(length.value.toInt() + 1)
            r = FFI.pbmx_rngs(this.handle, indices, length, names, namesLength, rngs)
            assert(r != 0)
            indices[indices.size - 1] = names.size.toLong()
            val offsets = indices.fold(ArrayList<Pair<Int, Int>>()) { l, i ->
                if (i > 0) {
                    val begin = if (l.size > 0) l.last().second else 0
                    l.add(Pair(begin, i.toInt()))
                }
                l
            }
            val strings = offsets.map { String(names, it.first, it.second - it.first) }.toList()

            return strings.zip(rngs.map { Rng(it) }).toMap()
        }

    fun genRandom(name: String): Long {
        val rng = this.rngs.getValue(name)
        val res = LongByReference()
        val r = FFI.pbmx_rng_gen(this.handle, rng.handle, res)
        assert(r != 0)
        return res.value
    }

    fun finalize() {
        FFI.pbmx_delete(this.handle)
    }
}
