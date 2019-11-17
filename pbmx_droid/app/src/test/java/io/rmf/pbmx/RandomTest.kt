package io.rmf.pbmx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RandomTest : TestBase() {

    @Test
    fun randomPermutation_works() {
        val arr = randomPermutation(10)
        arr.sort()
        val perm = arr.toList()
        val sorted = longArrayOf(0L, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L).toList()
        assertEquals(sorted, perm)
    }

    @Test
    fun randomShift_works() {
        val n = randomShift(10)
        assertTrue(n < 10)
    }
}
