package io.rmf.pbmx

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels

class KeysTest : TestBase() {

    @Test
    fun privateKeyExporting_roundtrips() {
        val key = PrivateKey.random()
        val stream = ByteArrayOutputStream()
        key.writeTo(Channels.newChannel(stream))
        val recovered = PrivateKey.readFrom(ByteBuffer.wrap(stream.toByteArray()))
        assertEquals(key.publicKey.fingerprint, recovered.publicKey.fingerprint)
    }
}
