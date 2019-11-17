package io.rmf.pbmx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.nio.ByteBuffer

class VtmfTest : TestBase() {

    private lateinit var pbmx1: Pbmx
    private lateinit var pbmx2: Pbmx

    private val token = Token.encode(17L)
    private val tokens1 = (1L..10L).map { Token.encode(it) }
    private val tokens2 = (101L..110L).map { Token.encode(it) }

    @Before
    fun exchangeNewKeys() {
        pbmx1 = Pbmx(PrivateKey.random())
        pbmx2 = Pbmx(PrivateKey.random())

        pbmx1.addKey(pbmx2.publicKey)
        pbmx2.addKey(pbmx1.publicKey)
    }

    @Test
    fun keyExchange_producesSameSharedKey() {
        assertEquals(pbmx1.sharedKey.fingerprint, pbmx2.sharedKey.fingerprint)
    }

    @Test
    fun tokenEncoding_roundtrips() {
        val x = 17L
        val token = Token.encode(x)

        assertEquals(x, token.decode())
    }

    @Test
    fun masking_verifies() {
        val (mask, proof) = pbmx1.mask(token)
        assertTrue(pbmx2.verifyMask(token, mask, proof))
    }

    @Test
    fun remasking_verifies() {
        val (mask1, _) = pbmx1.mask(token)
        val (mask2, proof2) = pbmx1.mask(mask1)
        assertTrue(pbmx2.verifyMask(mask1, mask2, proof2))
    }

    @Test
    fun maskingAndUnmasking_roundtrip() {
        val (mask, _) = pbmx1.mask(token)
        val (share1, _) = pbmx1.share(mask)
        val unmasked = pbmx2.unmaskFull(mask, share1)

        assertEquals(token, unmasked)
    }

    @Test
    fun unmasking_producesSameTokenForBothParties() {
        val (mask, _) = pbmx1.mask(token)
        val (share1, _) = pbmx1.share(mask)
        val (share2, _) = pbmx2.share(mask)

        val token1 = pbmx1.unmaskFull(mask, share2)
        val token2 = pbmx2.unmaskFull(mask, share1)

        assertEquals(token1, token2)
    }

    @Test
    fun shuffling_verifies() {
        val stack = tokens1.map { pbmx1.mask(it).mask }.toList()
        val (shuffled, _, proof) = pbmx1.shuffle(stack)
        assertTrue(pbmx2.verifyShuffle(stack, shuffled, proof))
    }

    @Test
    fun shuffling_producesCorrectShuffle() {
        val stack = tokens1.map { pbmx1.mask(it).mask }.toList()
        val (shuffled, _, _) = pbmx1.shuffle(stack)

        val unmasked = shuffled.map {
            val (share, _) = pbmx2.share(it)
            pbmx1.unmaskFull(it, share)
        }

        assertEquals(tokens1.toSortedSet(), unmasked.toSortedSet())
    }

    @Test
    fun shuffling_unmasksToSameForBothParties() {
        val stack = tokens1.map { pbmx1.mask(it).mask }.toList()
        val (shuffled, _, _) = pbmx1.shuffle(stack)

        val shares1 = shuffled.map { pbmx1.share(it).share }.toList()
        val shares2 = shuffled.map { pbmx2.share(it).share }.toList()

        val tokens1 = shuffled.zip(shares2).map { pbmx1.unmaskFull(it.first, it.second) }.toList()
        val tokens2 = shuffled.zip(shares1).map { pbmx2.unmaskFull(it.first, it.second) }.toList()

        assertEquals(tokens1, tokens2)
    }

    @Test
    fun shifting_verifies() {
        val stack = tokens1.map { pbmx1.mask(it).mask }.toList()
        val (shifted, _, proof) = pbmx1.shift(stack)
        assertTrue(pbmx2.verifyShift(stack, shifted, proof))
    }

    @Test
    fun shifting_producesCorrectShift() {
        val stack = tokens1.map { pbmx1.mask(it).mask }.toList()
        val (shifted, _, _) = pbmx1.shift(stack)

        val unmasked = shifted.map {
            val (share, _) = pbmx2.share(it)
            pbmx1.unmaskFull(it, share)
        }
        val top = tokens1.drop(unmasked[0].decode().toInt() - 1)
        val bottom = tokens1.take(unmasked[0].decode().toInt() - 1)

        assertEquals(top.plus(bottom), unmasked)
    }

    @Test
    fun shifting_unmasksToSameForBothParties() {
        val stack = tokens1.map { pbmx1.mask(it).mask }.toList()
        val (shifted, _, _) = pbmx1.shift(stack)

        val shares1 = shifted.map { pbmx1.share(it).share }.toList()
        val shares2 = shifted.map { pbmx2.share(it).share }.toList()

        val tokens1 = shifted.zip(shares2).map { pbmx1.unmaskFull(it.first, it.second) }.toList()
        val tokens2 = shifted.zip(shares1).map { pbmx2.unmaskFull(it.first, it.second) }.toList()

        assertEquals(tokens1, tokens2)
    }

    @Test
    fun randomMasking_unmasksToSameForBothParties() {
        val ent1 = pbmx1.maskRandom()
        val ent2 = pbmx2.maskRandom()

        val mask = ent1 + ent2

        val (share1, _) = pbmx1.share(mask)
        val (share2, _) = pbmx2.share(mask)

        val xof1 = pbmx1.unmaskRandom(mask, share2)
        val xof2 = pbmx2.unmaskRandom(mask, share1)

        val bytes1 = ByteArray(100)
        val bytes2 = ByteArray(100)
        xof1.read(ByteBuffer.wrap(bytes1))
        xof2.read(ByteBuffer.wrap(bytes2))

        assertEquals(bytes1.toList(), bytes2.toList())
    }

    @Test
    fun entanglement_verifies() {
        val stack1 = tokens1.map { pbmx1.mask(it).mask }.toList()
        val stack2 = tokens2.map { pbmx1.mask(it).mask }.toList()
        val perm = (0L..9L).shuffled().toLongArray()
        val (shuffle1, secrets1, _) = pbmx1.shuffle(stack1, perm)
        val (shuffle2, secrets2, _) = pbmx1.shuffle(stack2, perm)
        val proof = pbmx1.proveEntanglement(
            listOf(stack1, stack2),
            listOf(shuffle1, shuffle2),
            perm,
            listOf(secrets1, secrets2)
        )
        assertTrue(pbmx2.verifyEntanglement(listOf(stack1, stack2), listOf(shuffle1, shuffle2), proof))
    }
}