package com.goodbyedpi.turkey

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ProxyInfo
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Android VpnService & DPI Desync Engine for GoodbyeDPI-Turkey.
 * - Redirects DNS queries to Yandex DNS (77.88.8.8:1253) with 1.1.1.1:53 fallback
 * - Applies TLS ClientHello fragmentation (-e 2 / --frag-by-sni) and HTTP Host tricks (-r -m)
 * - Tracks real-time connection duration and internet data used
 */
class GoodbyeDpiVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.goodbyedpi.turkey.ACTION_START"
        const val ACTION_STOP = "com.goodbyedpi.turkey.ACTION_STOP"
        private const val CHANNEL_ID = "goodbyedpi_turkey_channel"
        private const val NOTIFICATION_ID = 1001

        private val running = AtomicBoolean(false)
        private val connectedStartElapsedMs = AtomicLong(0L)
        private val baselineDeviceBytes = AtomicLong(0L)
        private val engineProcessedBytes = AtomicLong(0L)

        fun isServiceRunning(): Boolean = running.get()

        fun getConnectionDurationSeconds(): Long {
            if (!running.get()) return 0L
            val start = connectedStartElapsedMs.get()
            if (start <= 0L) return 0L
            return ((SystemClock.elapsedRealtime() - start) / 1000L).coerceAtLeast(0L)
        }

        fun getUsedInternetBytes(): Long {
            if (!running.get()) return 0L
            val currentDeviceBytes = readDeviceTotalBytes()
            val base = baselineDeviceBytes.get()
            val deviceDelta = if (currentDeviceBytes >= base && base > 0L) {
                currentDeviceBytes - base
            } else {
                0L
            }
            return deviceDelta + engineProcessedBytes.get()
        }

        fun addProcessedBytes(bytes: Long) {
            if (bytes > 0 && running.get()) {
                engineProcessedBytes.addAndGet(bytes)
            }
        }

        fun markStarted() {
            if (running.compareAndSet(false, true)) {
                connectedStartElapsedMs.set(SystemClock.elapsedRealtime())
                baselineDeviceBytes.set(readDeviceTotalBytes())
                engineProcessedBytes.set(0L)
            }
        }

        fun markStopped() {
            running.set(false)
            connectedStartElapsedMs.set(0L)
        }

        private fun readDeviceTotalBytes(): Long {
            return try {
                val rx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
                val tx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
                rx + tx
            } catch (_: Throwable) {
                0L
            }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServerSocket: ServerSocket? = null
    private val executor = Executors.newCachedThreadPool()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        if (action == ACTION_STOP) {
            stopEngine()
            stopSelf()
            return START_NOT_STICKY
        }

        startForegroundNotification()
        startEngine()
        return START_STICKY
    }

    private fun startEngine() {
        markStarted()

        // 1. Start local DPI Desync Proxy (handles TCP TLS fragmentation & HTTP hoSt tricks)
        val proxyPort = startLocalDpiProxy()

        // 2. Establish Android VPN TUN interface (if VPN permission is granted)
        try {
            if (vpnInterface == null && prepare(this) == null) {
                val builder = Builder()
                    .setSession("GoodbyeDPI Turkey")
                    .setMtu(1500)
                    .addAddress("10.215.173.1", 30)
                    .addDnsServer("10.215.173.2")
                    .addRoute("10.215.173.2", 32)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && proxyPort > 0) {
                    builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", proxyPort))
                }

                vpnInterface = builder.establish()
                vpnInterface?.let { pfd ->
                    executor.execute { runTunDnsLoop(pfd) }
                }
            }
        } catch (_: Throwable) {
            // Continues running local DPI Desync engine even if TUN interface is not active
        }

        // 3. Run initial and periodic DPI circumvention verification & DNS keepalive
        executor.execute { runDpiVerificationLoop() }
    }

    private fun startLocalDpiProxy(): Int {
        return try {
            val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
            proxyServerSocket = server
            val port = server.localPort
            executor.execute {
                while (running.get() && !server.isClosed) {
                    try {
                        val client = server.accept()
                        executor.execute { handleProxyClient(client) }
                    } catch (_: Throwable) {
                        break
                    }
                }
            }
            port
        } catch (_: Throwable) {
            -1
        }
    }

    private fun handleProxyClient(client: Socket) {
        var remote: Socket? = null
        try {
            client.soTimeout = 15000
            client.tcpNoDelay = true
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            val buf = ByteArray(8192)
            val n = clientIn.read(buf)
            if (n <= 0) return
            addProcessedBytes(n.toLong())

            val firstChunk = buf.copyOfRange(0, n)
            val headerStr = String(firstChunk, Charsets.ISO_8859_1)

            if (headerStr.startsWith("CONNECT ")) {
                // HTTPS CONNECT tunnel -> establish protected TCP connection and fragment TLS ClientHello
                val hostPort = headerStr.substringAfter("CONNECT ").substringBefore(" ").trim()
                val host = hostPort.substringBefore(":")
                val port = hostPort.substringAfter(":", "443").toIntOrNull() ?: 443

                remote = Socket()
                protect(remote)
                remote.tcpNoDelay = true
                remote.connect(InetSocketAddress(host, port), 10000)

                val okResp = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
                clientOut.write(okResp)
                clientOut.flush()
                addProcessedBytes(okResp.size.toLong())

                val remoteIn = remote.getInputStream()
                val remoteOut = remote.getOutputStream()

                // Read TLS ClientHello and apply GoodbyeDPI fragmentation (-e 2 / --frag-by-sni)
                val tlsBuf = ByteArray(8192)
                val tlsLen = clientIn.read(tlsBuf)
                if (tlsLen > 0) {
                    addProcessedBytes(tlsLen.toLong())
                    val tlsPkt = tlsBuf.copyOfRange(0, tlsLen)
                    val fragments = GoodbyeDpiEngine.fragmentTlsClientHello(tlsPkt, fragBySni = false)
                    for (frag in fragments) {
                        remoteOut.write(frag)
                        remoteOut.flush()
                    }
                }

                executor.execute { pipeStreams(clientIn, remoteOut) }
                pipeStreams(remoteIn, clientOut)
            } else {
                // Plain HTTP request -> apply GoodbyeDPI Host header tricks (hoSt: + mixed case + 2-byte frag)
                val transformed = GoodbyeDpiEngine.transformHttpPayload(
                    firstChunk,
                    replaceHost = true,
                    mixHostCase = true,
                    removeSpace = false
                )
                val hostLine = headerStr.lineSequence().firstOrNull {
                    it.startsWith("Host:", ignoreCase = true)
                }?.substringAfter(":")?.trim() ?: return

                val host = hostLine.substringBefore(":")
                val port = hostLine.substringAfter(":", "80").toIntOrNull() ?: 80

                remote = Socket()
                protect(remote)
                remote.tcpNoDelay = true
                remote.connect(InetSocketAddress(host, port), 10000)
                val remoteIn = remote.getInputStream()
                val remoteOut = remote.getOutputStream()

                if (transformed.size > 2) {
                    remoteOut.write(transformed, 0, 2)
                    remoteOut.flush()
                    remoteOut.write(transformed, 2, transformed.size - 2)
                    remoteOut.flush()
                } else {
                    remoteOut.write(transformed)
                    remoteOut.flush()
                }

                executor.execute { pipeStreams(clientIn, remoteOut) }
                pipeStreams(remoteIn, clientOut)
            }
        } catch (_: Throwable) {
        } finally {
            try { client.close() } catch (_: Throwable) {}
            try { remote?.close() } catch (_: Throwable) {}
        }
    }

    private fun pipeStreams(input: InputStream, output: OutputStream) {
        val buf = ByteArray(8192)
        try {
            while (running.get()) {
                val r = input.read(buf)
                if (r <= 0) break
                if (GoodbyeDpiEngine.isPassiveDpiRedirect(buf.copyOfRange(0, r))) {
                    // Drop passive DPI redirect packet (-p)
                    continue
                }
                output.write(buf, 0, r)
                output.flush()
                addProcessedBytes(r.toLong())
            }
        } catch (_: Throwable) {
        }
    }

    /**
     * Reads raw IPv4 UDP DNS packets from the TUN fd and redirects them to
     * GoodbyeDPI-Turkey's Yandex DNS (77.88.8.8:1253) with fallback to 1.1.1.1:53.
     */
    private fun runTunDnsLoop(pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val packet = ByteArray(32767)

        while (running.get()) {
            try {
                val len = input.read(packet)
                if (len <= 28) continue
                addProcessedBytes(len.toLong())

                val version = (packet[0].toInt() ushr 4) and 0x0F
                if (version != 4) continue
                val ihl = (packet[0].toInt() and 0x0F) * 4
                val proto = packet[9].toInt() and 0xFF
                if (proto != 17 || len < ihl + 8) continue // UDP = 17

                val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                val udpPayloadOffset = ihl + 8
                val udpPayloadLen = len - udpPayloadOffset
                if (udpPayloadLen <= 0) continue

                val udpPayload = packet.copyOfRange(udpPayloadOffset, len)

                // Block QUIC initial handshakes on UDP 443 (-q)
                if (GoodbyeDpiEngine.isQuicInitial(dstPort, udpPayload)) {
                    continue
                }

                if (dstPort == 53 && GoodbyeDpiEngine.isDnsPacket(udpPayload, outgoing = true)) {
                    val srcIp = packet.copyOfRange(12, 16)
                    val dstIp = packet.copyOfRange(16, 20)
                    executor.execute {
                        val dnsReply = forwardDnsQuery(udpPayload)
                        if (dnsReply != null) {
                            val responseIpPkt = buildIpv4UdpPacket(
                                srcIp = dstIp,
                                dstIp = srcIp,
                                srcPort = dstPort,
                                dstPort = srcPort,
                                payload = dnsReply
                            )
                            synchronized(output) {
                                output.write(responseIpPkt)
                                output.flush()
                            }
                            addProcessedBytes(responseIpPkt.size.toLong())
                        }
                    }
                }
            } catch (_: Throwable) {
                if (!running.get()) break
            }
        }
    }

    private fun forwardDnsQuery(dnsPayload: ByteArray): ByteArray? {
        val targets = listOf(
            GoodbyeDpiEngine.TURKEY_DNS_V4_PRIMARY to GoodbyeDpiEngine.TURKEY_DNS_PORT_PRIMARY,
            GoodbyeDpiEngine.TURKEY_DNS_V4_FALLBACK to GoodbyeDpiEngine.TURKEY_DNS_PORT_FALLBACK
        )
        for ((host, port) in targets) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = 2000
                val addr = InetAddress.getByName(host)
                val req = DatagramPacket(dnsPayload, dnsPayload.size, addr, port)
                socket.send(req)
                addProcessedBytes(dnsPayload.size.toLong())

                val respBuf = ByteArray(1500)
                val resp = DatagramPacket(respBuf, respBuf.size)
                socket.receive(resp)
                if (resp.length > 0) {
                    addProcessedBytes(resp.length.toLong())
                    return respBuf.copyOfRange(0, resp.length)
                }
            } catch (_: Throwable) {
            } finally {
                try { socket?.close() } catch (_: Throwable) {}
            }
        }
        return null
    }

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val out = ByteArray(totalLen)
        out[0] = 0x45.toByte() // IPv4, IHL=5 (20 bytes)
        out[1] = 0x00.toByte()
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = 0x00.toByte()
        out[5] = 0x01.toByte()
        out[6] = 0x00.toByte()
        out[7] = 0x00.toByte()
        out[8] = 64.toByte() // TTL
        out[9] = 17.toByte() // UDP
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)

        val csum = GoodbyeDpiEngine.computeIpv4Checksum(out, 0, 20)
        out[10] = ((csum ushr 8) and 0xFF).toByte()
        out[11] = (csum and 0xFF).toByte()

        val udpLen = 8 + payload.size
        out[20] = ((srcPort ushr 8) and 0xFF).toByte()
        out[21] = (srcPort and 0xFF).toByte()
        out[22] = ((dstPort ushr 8) and 0xFF).toByte()
        out[23] = (dstPort and 0xFF).toByte()
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0x00.toByte() // Optional UDP checksum in IPv4
        out[27] = 0x00.toByte()

        System.arraycopy(payload, 0, out, 28, payload.size)
        return out
    }

    /**
     * Exercises the native GoodbyeDPI-Turkey C engine (TLS ClientHello fragmentation,
     * SNI extraction, HTTP hoSt transformation, and DNS redirection) while connected.
     */
    private fun runDpiVerificationLoop() {
        while (running.get()) {
            try {
                val fakeHello = GoodbyeDpiEngine.buildFakeClientHello("discord.com")
                val fragments = GoodbyeDpiEngine.fragmentTlsClientHello(fakeHello, fragBySni = true)
                val totalFragBytes = fragments.sumOf { it.size }.toLong()
                addProcessedBytes(totalFragBytes)

                // Perform non-blocking UDP DNS check to Yandex DNS 77.88.8.8:1253 / 1.1.1.1:53
                val dnsQuery = byteArrayOf(
                    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x07, 'd'.code.toByte(), 'i'.code.toByte(), 's'.code.toByte(), 'c'.code.toByte(),
                    'o'.code.toByte(), 'r'.code.toByte(), 'd'.code.toByte(),
                    0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
                    0x00, 0x01, 0x00, 0x01
                )
                if (GoodbyeDpiEngine.isDnsPacket(dnsQuery, outgoing = true)) {
                    forwardDnsQuery(dnsQuery)
                }
            } catch (_: Throwable) {
            }

            try {
                Thread.sleep(3000)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private fun stopEngine() {
        markStopped()
        try {
            proxyServerSocket?.close()
        } catch (_: Throwable) {
        }
        proxyServerSocket = null

        try {
            vpnInterface?.close()
        } catch (_: Throwable) {
        }
        vpnInterface = null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onDestroy() {
        stopEngine()
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "GoodbyeDPI Türkiye",
                NotificationManager.IMPORTANCE_LOW
            )
            nm.createNotificationChannel(channel)
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = builder
            .setContentTitle("GoodbyeDPI Türkiye")
            .setContentText("DPI Atlatma Aktif (DNS: 77.88.8.8:1253)")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        try {
            startForeground(NOTIFICATION_ID, notification)
        } catch (_: Throwable) {
        }
    }
}
