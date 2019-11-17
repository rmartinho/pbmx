package io.rmf.pbmx

import io.rmf.pbmx.payloads.BytesPayload
import io.rmf.pbmx.payloads.PublishKeyPayload
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels

class ChainTest : TestBase() {

    private lateinit var pbmx1: Pbmx
    private lateinit var pbmx2: Pbmx
    private lateinit var block1: Block
    private lateinit var block2: Block

    @Before
    fun exchangeNewKeys() {
        pbmx1 = Pbmx(PrivateKey.random())
        pbmx2 = Pbmx(PrivateKey.random())

        block1 = pbmx1.addBlock {
            it.publishKey("one", pbmx1.publicKey)
        }
        block2 = pbmx2.addBlock {
            it.publishKey("two", pbmx2.publicKey)
        }

        pbmx1.addBlock(block2)
        pbmx2.addBlock(block1)
    }

    @Test
    fun blockSigner_isCorrect() {
        assertEquals(pbmx1.publicKey.fingerprint, block1.signer)
        assertEquals(pbmx2.publicKey.fingerprint, block2.signer)
    }

    @Test
    fun parties_givesCorrectNameFingerprintPairs() {
        val expected = mapOf(
            Pair(pbmx1.publicKey.fingerprint, "one"),
            Pair(pbmx2.publicKey.fingerprint, "two")
        )
        assertEquals(expected, pbmx1.parties)
    }

    @Test
    fun blockExporting_roundtrips() {
        val block = pbmx1.buildBlock {
            it.randomSpec("6-sided die", "1d6")
        }
        val stream = ByteArrayOutputStream()
        block.writeTo(Channels.newChannel(stream))
        val recovered = Block.readFrom(ByteBuffer.wrap(stream.toByteArray()))
        assertEquals(block.id, recovered.id)
    }

    @Test
    fun validateBlock_isTrueForValidBlocks() {
        assertTrue(pbmx1.validateBlock(block1))
        assertTrue(pbmx1.validateBlock(block2))
    }

    @Test
    fun validateBlock_isFalseForInvalidBlocks() {
        val pbmx3 = Pbmx(PrivateKey.random())
        val block3 = pbmx3.addBlock {
            it.publishKey("three", pbmx3.publicKey)
        }
        assertFalse(pbmx1.validateBlock(block3))
    }

    @Test
    fun blocks_iteratesCorrectly() {
        val block3 = pbmx1.buildBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        val block4 = pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(9, 8, 7, 6, 5)))
        }
        val block5 = pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(4, 3, 2, 1, 0)))
        }
        pbmx1.addBlock(block3)

        val ids = pbmx1.blocks.map { it.id }
        val expected = arrayOf(block1, block2, block3, block4, block5).map { it.id }
        assertEquals(expected.toSortedSet(), ids.toSortedSet())
    }

    @Test
    fun heads_iteratesCorrectly() {
        val block3 = pbmx1.buildBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(9, 8, 7, 6, 5)))
        }
        val block5 = pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(4, 3, 2, 1, 0)))
        }
        pbmx1.addBlock(block3)

        val ids = pbmx1.heads.map { it.id }
        val expected = arrayOf(block3, block5).map { it.id }
        assertEquals(expected.toSortedSet(), ids.toSortedSet())
    }

    @Test
    fun roots_iteratesCorrectly() {
        val block3 = pbmx1.buildBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(9, 8, 7, 6, 5)))
        }
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(4, 3, 2, 1, 0)))
        }
        pbmx1.addBlock(block3)

        val ids = pbmx1.roots.map { it.id }
        val expected = arrayOf(block1, block2).map { it.id }
        assertEquals(expected.toSortedSet(), ids.toSortedSet())
    }

    @Test
    fun merged_isTrueForMergedChains() {
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        assertTrue(pbmx1.merged)
    }

    @Test
    fun merged_isFalseForDivergentChains() {
        val block3 = pbmx1.buildBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(9, 8, 7, 6, 5)))
        }
        pbmx1.addBlock(block3)
        assertFalse(pbmx1.merged)
    }

    @Test
    fun empty_isTrueForEmptyChains() {
        val pbmx3 = Pbmx(PrivateKey.random())
        assertTrue(pbmx3.empty)
    }

    @Test
    fun empty_isFalseForEmptyChains() {
        assertFalse(pbmx1.empty)
    }

    @Test
    fun incomplete_isTrueForIncompleteChains() {
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        val block4 = pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(9, 8, 7, 6, 5)))
        }
        pbmx2.addBlock(block4)
        assertTrue(pbmx2.incomplete)
    }

    @Test
    fun incomplete_isFalseForCompleteChains() {
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(9, 8, 7, 6, 5)))
        }
        assertFalse(pbmx1.incomplete)
    }

    @Test
    fun parentsOf_iteratesCorrectly() {
        val block3 = pbmx1.addBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        val ids = pbmx1.parentsOf(block3).map { it.id }
        val expected = arrayOf(block1, block2).map { it.id }
        assertEquals(expected.toSortedSet(), ids.toSortedSet())
    }

    @Test
    fun payloads_iteratesCorrectly() {
        val block3 = pbmx1.buildBlock {
            it.bytes(ByteBuffer.wrap(byteArrayOf(0, 1, 2, 3, 4)))
            it.bytes(ByteBuffer.wrap(byteArrayOf(5, 6, 7, 8, 9)))
        }
        val payloads1 = block1.payloads
        assertEquals(1, payloads1.size)
        assertEquals(PublishKeyPayload::class.java, payloads1[0].javaClass)
        assertEquals("one", (payloads1[0] as PublishKeyPayload).name)
        assertEquals(pbmx1.publicKey.fingerprint, (payloads1[0] as PublishKeyPayload).key.fingerprint)
        val payloads2 = block2.payloads
        assertEquals(1, payloads2.size)
        assertEquals(PublishKeyPayload::class.java, payloads2[0].javaClass)
        assertEquals("two", (payloads2[0] as PublishKeyPayload).name)
        assertEquals(pbmx2.publicKey.fingerprint, (payloads2[0] as PublishKeyPayload).key.fingerprint)
        val payloads3 = block3.payloads
        assertEquals(2, payloads3.size)
        assertEquals(BytesPayload::class.java, payloads3[0].javaClass)
        assertEquals(byteArrayOf(0, 1, 2, 3, 4).toList(), (payloads3[0] as BytesPayload).bytes.toList())
        assertEquals(BytesPayload::class.java, payloads3[1].javaClass)
        assertEquals(byteArrayOf(5, 6, 7, 8, 9).toList(), (payloads3[1] as BytesPayload).bytes.toList())
    }
}
