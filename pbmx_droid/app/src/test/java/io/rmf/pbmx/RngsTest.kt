package io.rmf.pbmx

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class RngsTest : TestBase() {

    private lateinit var pbmx1: Pbmx
    private lateinit var pbmx2: Pbmx

    @Before
    fun exchangeNewKeys() {
        pbmx1 = Pbmx(PrivateKey.random())
        pbmx2 = Pbmx(PrivateKey.random())

        val block1 = pbmx1.addBlock {
            it.publishKey("one", pbmx1.publicKey)
        }
        val block2 = pbmx2.addBlock {
            it.publishKey("two", pbmx2.publicKey)
        }

        pbmx1.addBlock(block2)
        pbmx2.addBlock(block1)
    }

    @Test
    fun rngs_iteratesCorrectly() {
        pbmx1.addBlock {
            it.randomSpec("die", "1d6")
        }
        pbmx1.addBlock {
            it.randomSpec("dice", "2d6")
        }

        val nameSpecPairs = pbmx1.rngs.map { Pair(it.key, it.value.spec) }.toMap()
        val expected = mapOf(Pair("die", "1d6"), Pair("dice", "2d6"))
        assertEquals(expected.toSortedMap(), nameSpecPairs.toSortedMap())
    }

    @Test
    fun rngMask_isSameOnAllParties() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)
        val block4 = pbmx2.addBlock {
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx1.addBlock(block4)

        assertEquals(pbmx1.rngs.getValue("die").mask, pbmx2.rngs.getValue("die").mask)
    }

    @Test
    fun rngGenerated_isFalseIfEntropyIsMissing() {
        pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        assertFalse(pbmx1.rngs.getValue("die").generated)
    }

    @Test
    fun rngGenerated_isTrueIfAllEntropyIsProvided() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)
        pbmx2.addBlock {
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        assertTrue(pbmx2.rngs.getValue("die").generated)
    }

    @Test
    fun rngRevealed_isFalseIfSecretsAreMissing() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)

        pbmx2.addBlock {
            it.randomEntropy("die", pbmx1.maskRandom())
        }
        val mask = pbmx2.rngs.getValue("die").mask
        pbmx2.addBlock {
            val (share, proof) = pbmx2.share(mask)
            it.randomReveal("die", share, proof)
        }

        assertFalse(pbmx1.rngs.getValue("die").revealed)
    }

    @Test
    fun rngRevealed_isTrueIfAllSecretsAreProvided() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)

        val block4 = pbmx2.addBlock {
            val rng = pbmx2.rngs.getValue("die")
            val entropy = pbmx2.maskRandom()
            rng.addEntropy(pbmx2.publicKey.fingerprint, entropy)
            it.randomEntropy("die", entropy)

            val (share, proof) = pbmx2.share(rng.mask)
            it.randomReveal("die", share, proof)
        }

        pbmx1.addBlock(block4)
        pbmx1.addBlock {
            val (share, proof) = pbmx1.share(pbmx1.rngs.getValue("die").mask)
            it.randomReveal("die", share, proof)
        }

        assertTrue(pbmx1.rngs.getValue("die").revealed)
    }

    @Test
    fun rngEntropyParties_iteratesCorrectly() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)
        pbmx2.addBlock {
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        val parties1 = pbmx1.rngs.getValue("die").entropyParties
        val fps1 = listOf(pbmx1.publicKey.fingerprint)
        assertEquals(fps1.toSortedSet(), parties1.toSortedSet())
        val parties2 = pbmx2.rngs.getValue("die").entropyParties
        val fps2 = listOf(pbmx1.publicKey.fingerprint, pbmx2.publicKey.fingerprint)
        assertEquals(fps2.toSortedSet(), parties2.toSortedSet())
    }

    @Test
    fun rngSecretParties_iteratesCorrectly() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)

        val block4 = pbmx2.addBlock {
            val rng = pbmx2.rngs.getValue("die")
            val entropy = pbmx2.maskRandom()
            rng.addEntropy(pbmx2.publicKey.fingerprint, entropy)
            it.randomEntropy("die", entropy)

            val (share, proof) = pbmx2.share(rng.mask)
            it.randomReveal("die", share, proof)
        }

        pbmx1.addBlock(block4)
        pbmx1.addBlock {
            val (share, proof) = pbmx1.share(pbmx1.rngs.getValue("die").mask)
            it.randomReveal("die", share, proof)
        }

        val parties1 = pbmx1.rngs.getValue("die").secretParties
        val fps1 = listOf(pbmx1.publicKey.fingerprint, pbmx2.publicKey.fingerprint)
        assertEquals(fps1.toSortedSet(), parties1.toSortedSet())
        val parties2 = pbmx2.rngs.getValue("die").secretParties
        val fps2 = listOf(pbmx2.publicKey.fingerprint)
        assertEquals(fps2.toSortedSet(), parties2.toSortedSet())
    }

    @Test
    fun genRandom_producesSameResultOnBothParties() {
        val block3 = pbmx1.addBlock {
            it.randomSpec("die", "1d6")
            it.randomEntropy("die", pbmx1.maskRandom())
        }

        pbmx2.addBlock(block3)

        val block4 = pbmx2.addBlock {
            val rng = pbmx2.rngs.getValue("die")
            val entropy = pbmx2.maskRandom()
            rng.addEntropy(pbmx2.publicKey.fingerprint, entropy)
            it.randomEntropy("die", entropy)

            val (share, proof) = pbmx2.share(rng.mask)
            it.randomReveal("die", share, proof)
        }

        pbmx1.addBlock(block4)
        val block5 = pbmx1.addBlock {
            val (share, proof) = pbmx1.share(pbmx1.rngs.getValue("die").mask)
            it.randomReveal("die", share, proof)
        }

        pbmx2.addBlock(block5)

        assertEquals(pbmx1.genRandom("die"), pbmx2.genRandom("die"))
    }
}