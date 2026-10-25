package com.goodbyedpi.turkey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GoodbyeDpiEngineTest {

    @Test
    fun testBuildFakeClientHelloAndExtractSni() {
        val domain = "turkiye.gov.tr"
        val clientHello = GoodbyeDpiEngine.buildFakeClientHello(domain)
        assertTrue(clientHello.size > 60)
        assertEquals(0x16.toByte(), clientHello[0])
        assertEquals(0x03.toByte(), clientHello[1])

        val extracted = GoodbyeDpiEngine.extractSni(clientHello)
        assertEquals(domain, extracted)
    }

    @Test
    fun testTlsClientHelloFragmentation() {
        val clientHello = GoodbyeDpiEngine.buildFakeClientHello("discord.com")
        // Default -e 2 split
        val fragsDefault = GoodbyeDpiEngine.fragmentTlsClientHello(clientHello, fragBySni = false)
        assertEquals(2, fragsDefault.size)
        assertEquals(2, fragsDefault[0].size)
        assertEquals(clientHello.size - 2, fragsDefault[1].size)

        // --frag-by-sni split
        val fragsBySni = GoodbyeDpiEngine.fragmentTlsClientHello(clientHello, fragBySni = true)
        assertEquals(2, fragsBySni.size)
        assertTrue(fragsBySni[0].size > 2)
        assertEquals(clientHello.size, fragsBySni[0].size + fragsBySni[1].size)
    }

    @Test
    fun testHttpHostHeaderTransformation() {
        val rawHttp = (
            "GET /index.html HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "User-Agent: Mozilla/5.0\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)

        val transformed = GoodbyeDpiEngine.transformHttpPayload(
            rawHttp,
            replaceHost = true,
            mixHostCase = true,
            removeSpace = false
        )
        val text = String(transformed, Charsets.ISO_8859_1)
        assertTrue("Host header should be replaced with hoSt:", text.contains("\r\nhoSt: "))
        assertTrue("Host value should have mixed case:", text.contains("eXaMpLe.cOm"))
    }

    @Test
    fun testPassiveDpiRedirectDetection() {
        val dpiRedirect = (
            "HTTP/1.1 302 Found\r\n" +
                "Location: http://warning.isp.com.tr/block\r\n" +
                "Connection: close\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        assertTrue(GoodbyeDpiEngine.isPassiveDpiRedirect(dpiRedirect))

        val normalResponse = (
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        assertFalse(GoodbyeDpiEngine.isPassiveDpiRedirect(normalResponse))
    }

    @Test
    fun testQuicInitialPacketDetection() {
        val quicPkt = ByteArray(1250)
        quicPkt[0] = 0xC3.toByte()
        quicPkt[1] = 0x00
        quicPkt[2] = 0x00
        quicPkt[3] = 0x00
        quicPkt[4] = 0x01
        assertTrue(GoodbyeDpiEngine.isQuicInitial(443, quicPkt))
        assertFalse(GoodbyeDpiEngine.isQuicInitial(80, quicPkt))
    }

    @Test
    fun testAutoTtlCalculation() {
        // Server initial TTL 64, 10 hops away -> received TTL = 54
        val fakeTtl = GoodbyeDpiEngine.getAutoTtl(54, 1, 4, 3, 10)
        assertEquals(6, fakeTtl)
    }

    @Test
    fun testFormatDurationAndBytes() {
        assertEquals("00:00:00", GoodbyeDpiEngine.formatDuration(0))
        assertEquals("00:01:05", GoodbyeDpiEngine.formatDuration(65))
        assertEquals("01:02:03", GoodbyeDpiEngine.formatDuration(3723))

        assertEquals("512 B", GoodbyeDpiEngine.formatBytes(512))
        assertEquals("2.00 KB", GoodbyeDpiEngine.formatBytes(2048))
        assertEquals("1.50 MB", GoodbyeDpiEngine.formatBytes(1572864))
    }
}
