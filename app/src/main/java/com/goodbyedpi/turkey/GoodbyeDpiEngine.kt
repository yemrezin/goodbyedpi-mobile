package com.goodbyedpi.turkey

import java.nio.ByteBuffer
import java.util.Locale

/**
 * GoodbyeDPI-Turkey (v0.2.3rc3-turkey) Mobile Packet & DPI Circumvention Engine.
 * Bridges the native C implementation (src/goodbyedpi.c, fakepackets.c, dnsredir.c, ttltrack.c)
 * with Android VpnService and provides pure-Kotlin fallbacks for host JVM unit tests.
 */
object GoodbyeDpiEngine {

    private var nativeLoaded = false

    init {
        try {
            System.loadLibrary("goodbyedpi_turkey")
            nativeLoaded = true
        } catch (_: UnsatisfiedLinkError) {
            nativeLoaded = false
        }
    }

    // Turkey fork default DNS servers (Yandex Safe DNS on port 1253 to bypass ISP port 53 interception)
    const val TURKEY_DNS_V4_PRIMARY = "77.88.8.8"
    const val TURKEY_DNS_PORT_PRIMARY = 1253
    const val TURKEY_DNS_V4_FALLBACK = "1.1.1.1"
    const val TURKEY_DNS_PORT_FALLBACK = 53

    private val HTTP_METHODS = arrayOf(
        "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS "
    )

    fun isNativeLoaded(): Boolean = nativeLoaded

    fun getVersion(): String {
        if (nativeLoaded) {
            return try {
                nativeGetVersion()
            } catch (_: Throwable) {
                "v0.2.3rc3-turkey-mobile"
            }
        }
        return "v0.2.3rc3-turkey-mobile"
    }

    /**
     * Extracts TLS ClientHello Server Name Indication (SNI) using GoodbyeDPI's algorithm.
     */
    fun extractSni(packet: ByteArray): String? {
        if (packet.size <= 8) return null
        if (nativeLoaded) {
            return try {
                nativeExtractSni(packet)
            } catch (_: Throwable) {
                extractSniKotlin(packet)
            }
        }
        return extractSniKotlin(packet)
    }

    private fun extractSniKotlin(d: ByteArray): String? {
        var ptr = 0
        val pktlen = d.size
        while (ptr + 8 < pktlen) {
            val b0 = d[ptr].toInt() and 0xFF
            val b1 = d[ptr + 1].toInt() and 0xFF
            val b2 = d[ptr + 2].toInt() and 0xFF
            val b3 = d[ptr + 3].toInt() and 0xFF
            val b4 = d[ptr + 4].toInt() and 0xFF
            val b5 = d[ptr + 5].toInt() and 0xFF
            val b6 = d[ptr + 6].toInt() and 0xFF
            val b7 = d[ptr + 7].toInt() and 0xFF
            val b8 = d[ptr + 8].toInt() and 0xFF

            if (b0 == 0 && b1 == 0 && b2 == 0 && b4 == 0 && b6 == 0 && b7 == 0 &&
                (b3 - b5 == 2) && (b5 - b8 == 3)
            ) {
                if (ptr + 9 + b8 > pktlen) return null
                if (b8 < 3 || b8 > 253) return null
                for (i in 0 until b8) {
                    val c = (d[ptr + 9 + i].toInt() and 0xFF).toChar()
                    val valid = (c in '0'..'9') || (c in 'a'..'z') || c == '.' || c == '-'
                    if (!valid) return null
                }
                return String(d, ptr + 9, b8, Charsets.US_ASCII)
            }
            ptr++
        }
        return null
    }

    /**
     * Calculates the TCP split offset for TLS ClientHello packets (-e 2 or --frag-by-sni).
     */
    fun calcTlsSplitOffset(packet: ByteArray, fragBySni: Boolean = false): Int {
        if (packet.size < 3) return -1
        if (nativeLoaded) {
            return try {
                nativeCalcTlsSplitOffset(packet, fragBySni)
            } catch (_: Throwable) {
                calcTlsSplitOffsetKotlin(packet, fragBySni)
            }
        }
        return calcTlsSplitOffsetKotlin(packet, fragBySni)
    }

    private fun calcTlsSplitOffsetKotlin(packet: ByteArray, fragBySni: Boolean): Int {
        val b0 = packet[0].toInt() and 0xFF
        val b1 = packet[1].toInt() and 0xFF
        val b2 = packet[2].toInt() and 0xFF
        if (b0 == 0x16 && b1 == 0x03 && b2 in 0x01..0x03) {
            if (fragBySni) {
                val sni = extractSniKotlin(packet)
                if (sni != null) {
                    val sniBytes = sni.toByteArray(Charsets.US_ASCII)
                    val idx = indexOfBytes(packet, sniBytes)
                    if (idx > 2 && idx < packet.size) {
                        return idx
                    }
                }
            }
            return 2 // GoodbyeDPI -e 2 default
        }
        return -1
    }

    /**
     * Splits a TLS ClientHello into fragmented segments to bypass DPI inspection (--native-frag).
     */
    fun fragmentTlsClientHello(
        packet: ByteArray,
        fragBySni: Boolean = false
    ): List<ByteArray> {
        val splitOffset = calcTlsSplitOffset(packet, fragBySni)
        if (splitOffset <= 0 || splitOffset >= packet.size) {
            return listOf(packet)
        }
        val firstPart = packet.copyOfRange(0, splitOffset)
        val secondPart = packet.copyOfRange(splitOffset, packet.size)
        return listOf(firstPart, secondPart)
    }

    /**
     * Transforms outbound HTTP requests using GoodbyeDPI tricks:
     * - Replaces "\r\nHost: " with "\r\nhoSt: " (-r)
     * - Mixes Host header value case (-m)
     * - Removes space after Host header (-s)
     */
    fun transformHttpPayload(
        packet: ByteArray,
        replaceHost: Boolean = true,
        mixHostCase: Boolean = true,
        removeSpace: Boolean = false
    ): ByteArray {
        if (packet.size <= 16) return packet
        if (nativeLoaded) {
            return try {
                nativeTransformHttpPayload(packet, replaceHost, mixHostCase, removeSpace)
            } catch (_: Throwable) {
                transformHttpPayloadKotlin(packet, replaceHost, mixHostCase)
            }
        }
        return transformHttpPayloadKotlin(packet, replaceHost, mixHostCase)
    }

    private fun transformHttpPayloadKotlin(
        packet: ByteArray,
        replaceHost: Boolean,
        mixHostCase: Boolean
    ): ByteArray {
        val text = String(packet, Charsets.ISO_8859_1)
        val startsWithMethod = HTTP_METHODS.any { text.startsWith(it) }
        if (!startsWithMethod) return packet

        val out = packet.copyOf()
        val hostHeader = "\r\nHost: ".toByteArray(Charsets.ISO_8859_1)
        val hostIdx = indexOfBytes(out, hostHeader)
        if (hostIdx >= 0) {
            val valStart = hostIdx + hostHeader.size
            val rnBytes = "\r\n".toByteArray(Charsets.ISO_8859_1)
            val valEnd = indexOfBytes(out, rnBytes, valStart)
            if (valEnd > valStart && (valEnd - valStart) in 3..253) {
                if (mixHostCase) {
                    for (i in 0 until (valEnd - valStart)) {
                        if (i % 2 == 1) {
                            val ch = (out[valStart + i].toInt() and 0xFF).toChar()
                            out[valStart + i] = ch.uppercaseChar().code.toByte()
                        }
                    }
                }
                if (replaceHost) {
                    val replacement = "\r\nhoSt: ".toByteArray(Charsets.ISO_8859_1)
                    System.arraycopy(replacement, 0, out, hostIdx, replacement.size)
                }
            }
        }
        return out
    }

    /**
     * Checks if an inbound HTTP response is a spoofed Passive DPI 302 redirect (-p).
     */
    fun isPassiveDpiRedirect(packet: ByteArray): Boolean {
        if (packet.size <= 16) return false
        if (nativeLoaded) {
            return try {
                nativeIsPassiveDpiRedirect(packet)
            } catch (_: Throwable) {
                isPassiveDpiRedirectKotlin(packet)
            }
        }
        return isPassiveDpiRedirectKotlin(packet)
    }

    private fun isPassiveDpiRedirectKotlin(packet: ByteArray): Boolean {
        val str = String(packet, Charsets.ISO_8859_1)
        if (str.startsWith("HTTP/1.1 302 ") || str.startsWith("HTTP/1.0 302 ")) {
            return str.contains("\r\nLocation: http://") && str.contains("\r\nConnection: close")
        }
        return false
    }

    /**
     * Checks if an outbound UDP packet is a QUIC Initial handshake packet to block (-q).
     */
    fun isQuicInitial(dstPort: Int, udpPayload: ByteArray): Boolean {
        if (dstPort != 443 || udpPayload.size < 1200) return false
        if (nativeLoaded) {
            return try {
                nativeIsQuicInitial(dstPort, udpPayload)
            } catch (_: Throwable) {
                isQuicInitialKotlin(dstPort, udpPayload)
            }
        }
        return isQuicInitialKotlin(dstPort, udpPayload)
    }

    private fun isQuicInitialKotlin(dstPort: Int, u: ByteArray): Boolean {
        if (dstPort != 443 || u.size < 1200) return false
        val b0 = u[0].toInt() and 0xFF
        return b0 >= 0xC0 &&
                u[1].toInt() == 0x00 &&
                u[2].toInt() == 0x00 &&
                u[3].toInt() == 0x00 &&
                u[4].toInt() == 0x01
    }

    /**
     * Generates a Firefox 130 fake TLS ClientHello packet with the specified SNI (fakepackets.c).
     */
    fun buildFakeClientHello(domainName: String = "www.w3.org"): ByteArray {
        if (nativeLoaded) {
            return try {
                nativeBuildFakeClientHello(domainName)
            } catch (_: Throwable) {
                buildFakeClientHelloKotlin(domainName)
            }
        }
        return buildFakeClientHelloKotlin(domainName)
    }

    private fun buildFakeClientHelloKotlin(domainName: String): ByteArray {
        val domainBytes = domainName.toByteArray(Charsets.US_ASCII)
        val sniExtLen = domainBytes.size + 5
        val sniListLen = domainBytes.size + 3
        val out = ByteBuffer.allocate(64 + domainBytes.size)
        // TLS Record Header (Handshake 0x16, TLS 1.0/1.2)
        out.put(0x16.toByte())
        out.put(0x03.toByte())
        out.put(0x01.toByte())
        out.putShort((59 + domainBytes.size).toShort())
        // ClientHello Header
        out.put(0x01.toByte())
        out.put(0x00.toByte())
        out.putShort((55 + domainBytes.size).toShort())
        out.put(0x03.toByte())
        out.put(0x03.toByte())
        // 32-byte random + sessionId(0) + cipherSuites(2) + compression(1)
        out.put(ByteArray(32) { 0x42 })
        out.put(0x00.toByte())
        out.putShort(0x0002.toShort())
        out.putShort(0x1301.toShort())
        out.put(0x01.toByte())
        out.put(0x00.toByte())
        // Extensions length
        out.putShort((sniExtLen + 4).toShort())
        // SNI extension (0x0000)
        out.putShort(0x0000.toShort())
        out.putShort(sniExtLen.toShort())
        out.putShort(sniListLen.toShort())
        out.put(0x00.toByte())
        out.putShort(domainBytes.size.toShort())
        out.put(domainBytes)
        return out.array()
    }

    /**
     * Checks if a UDP payload is a valid DNS request/response (from dnsredir.c).
     */
    fun isDnsPacket(payload: ByteArray, outgoing: Boolean): Boolean {
        if (payload.size < 16) return false
        if (nativeLoaded) {
            return try {
                nativeIsDnsPacket(payload, outgoing)
            } catch (_: Throwable) {
                isDnsPacketKotlin(payload, outgoing)
            }
        }
        return isDnsPacketKotlin(payload, outgoing)
    }

    private fun isDnsPacketKotlin(payload: ByteArray, outgoing: Boolean): Boolean {
        if (payload.size < 16) return false
        val flags = ((payload[2].toInt() and 0xFF) shl 8) or (payload[3].toInt() and 0xFF)
        return if (outgoing) {
            val anAndNsCount = ((payload[6].toInt() and 0xFF) shl 24) or
                    ((payload[7].toInt() and 0xFF) shl 16) or
                    ((payload[8].toInt() and 0xFF) shl 8) or
                    (payload[9].toInt() and 0xFF)
            (flags and 0xFA00) == 0 && anAndNsCount == 0
        } else {
            (flags and 0xF800) == 0x8000
        }
    }

    /**
     * Calculates Auto-TTL value for fake packets based on server SYN-ACK TTL (from ttltrack.c).
     */
    fun getAutoTtl(
        ttl: Int,
        autottl1: Int = 1,
        autottl2: Int = 4,
        minhops: Int = 3,
        maxttl: Int = 10
    ): Int {
        if (nativeLoaded) {
            return try {
                nativeGetAutoTtl(ttl, autottl1, autottl2, minhops, maxttl)
            } catch (_: Throwable) {
                getAutoTtlKotlin(ttl, autottl1, autottl2, minhops, maxttl)
            }
        }
        return getAutoTtlKotlin(ttl, autottl1, autottl2, minhops, maxttl)
    }

    private fun getAutoTtlKotlin(
        ttl: Int,
        autottl1: Int,
        autottl2: Int,
        minhops: Int,
        maxttl: Int
    ): Int {
        val nhops = when {
            ttl in 99..127 -> 128 - ttl
            ttl in 35..63 -> 64 - ttl
            else -> return 0
        }
        if (nhops <= autottl1 || nhops < minhops) return 0
        var fakeTtl = nhops - autottl2
        if (fakeTtl < autottl2 && nhops <= 9) {
            fakeTtl = nhops - autottl1 - ((autottl2 - autottl1) * (nhops / 10.0f)).toInt()
        }
        if (maxttl > 0 && fakeTtl > maxttl) {
            fakeTtl = maxttl
        }
        return fakeTtl
    }

    /**
     * Formats connection duration in HH:MM:SS format.
     */
    fun formatDuration(seconds: Long): String {
        val safeSec = seconds.coerceAtLeast(0L)
        val hrs = safeSec / 3600
        val mins = (safeSec % 3600) / 60
        val secs = safeSec % 60
        return String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
    }

    /**
     * Formats byte count into human-readable internet usage string (B / KB / MB / GB).
     */
    fun formatBytes(bytes: Long): String {
        val safeBytes = bytes.coerceAtLeast(0L)
        return when {
            safeBytes < 1024L -> "$safeBytes B"
            safeBytes < 1024L * 1024L -> String.format(Locale.US, "%.2f KB", safeBytes / 1024.0)
            safeBytes < 1024L * 1024L * 1024L -> String.format(
                Locale.US,
                "%.2f MB",
                safeBytes / (1024.0 * 1024.0)
            )
            else -> String.format(
                Locale.US,
                "%.2f GB",
                safeBytes / (1024.0 * 1024.0 * 1024.0)
            )
        }
    }

    /**
     * Computes standard RFC 1071 16-bit one's complement IPv4 header checksum.
     */
    fun computeIpv4Checksum(header: ByteArray, offset: Int = 0, length: Int = 20): Int {
        var sum = 0
        var i = 0
        while (i < length - 1) {
            val word = ((header[offset + i].toInt() and 0xFF) shl 8) or
                    (header[offset + i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < length) {
            sum += (header[offset + i].toInt() and 0xFF) shl 8
        }
        while ((sum shr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray, startIndex: Int = 0): Int {
        if (needle.isEmpty() || haystack.size - startIndex < needle.size) return -1
        for (i in startIndex..(haystack.size - needle.size)) {
            var match = true
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) {
                    match = false
                    break
                }
            }
            if (match) return i
        }
        return -1
    }

    private external fun nativeGetVersion(): String
    private external fun nativeExtractSni(packet: ByteArray): String?
    private external fun nativeCalcTlsSplitOffset(packet: ByteArray, fragBySni: Boolean): Int
    private external fun nativeTransformHttpPayload(
        packet: ByteArray,
        replaceHost: Boolean,
        mixHostCase: Boolean,
        removeSpace: Boolean
    ): ByteArray
    private external fun nativeIsPassiveDpiRedirect(packet: ByteArray): Boolean
    private external fun nativeIsQuicInitial(dstPort: Int, udpPayload: ByteArray): Boolean
    private external fun nativeBuildFakeClientHello(domainName: String): ByteArray
    private external fun nativeIsDnsPacket(payload: ByteArray, outgoing: Boolean): Boolean
    private external fun nativeGetAutoTtl(
        ttl: Int,
        autottl1: Int,
        autottl2: Int,
        minhops: Int,
        maxttl: Int
    ): Int
}
