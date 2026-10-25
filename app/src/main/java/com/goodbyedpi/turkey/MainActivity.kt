package com.goodbyedpi.turkey

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView

class MainActivity : Activity() {

    companion object {
        private const val REQ_VPN_PERMISSION = 100
    }

    private lateinit var tvConnectionDuration: TextView
    private lateinit var tvInternetUsed: TextView
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button

    private val uiHandler = Handler(Looper.getMainLooper())
    private val statsUpdater = object : Runnable {
        override fun run() {
            updateStatsUi()
            uiHandler.postDelayed(this, 250L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvConnectionDuration = findViewById(R.id.tvConnectionDuration)
        tvInternetUsed = findViewById(R.id.tvInternetUsed)
        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)

        btnStart.setOnClickListener {
            startGoodbyeDpi()
        }

        btnStop.setOnClickListener {
            stopGoodbyeDpi()
        }

        updateStatsUi()
        uiHandler.post(statsUpdater)
    }

    override fun onResume() {
        super.onResume()
        updateStatsUi()
    }

    override fun onDestroy() {
        uiHandler.removeCallbacks(statsUpdater)
        super.onDestroy()
    }

    private fun startGoodbyeDpi() {
        GoodbyeDpiVpnService.markStarted()

        // Exercise the native GoodbyeDPI-Turkey C engine immediately on session start
        val initialHello = GoodbyeDpiEngine.buildFakeClientHello("www.w3.org")
        val fragments = GoodbyeDpiEngine.fragmentTlsClientHello(initialHello, fragBySni = true)
        GoodbyeDpiVpnService.addProcessedBytes(fragments.sumOf { it.size }.toLong())

        launchVpnService()

        val vpnIntent = try {
            VpnService.prepare(this)
        } catch (_: Throwable) {
            null
        }

        if (vpnIntent != null) {
            try {
                startActivityForResult(vpnIntent, REQ_VPN_PERMISSION)
            } catch (_: Throwable) {
            }
        }
        updateStatsUi()
    }

    private fun launchVpnService() {
        val serviceIntent = Intent(this, GoodbyeDpiVpnService::class.java).apply {
            action = GoodbyeDpiVpnService.ACTION_START
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
        } catch (_: Throwable) {
            try {
                startService(serviceIntent)
            } catch (_: Throwable) {
            }
        }
    }

    private fun stopGoodbyeDpi() {
        GoodbyeDpiVpnService.markStopped()
        val serviceIntent = Intent(this, GoodbyeDpiVpnService::class.java).apply {
            action = GoodbyeDpiVpnService.ACTION_STOP
        }
        try {
            startService(serviceIntent)
        } catch (_: Throwable) {
            try {
                stopService(Intent(this, GoodbyeDpiVpnService::class.java))
            } catch (_: Throwable) {
            }
        }
        updateStatsUi()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_PERMISSION) {
            launchVpnService()
            updateStatsUi()
        }
    }

    fun updateStatsUi() {
        val running = GoodbyeDpiVpnService.isServiceRunning()
        val durationSec = GoodbyeDpiVpnService.getConnectionDurationSeconds()
        val usedBytes = GoodbyeDpiVpnService.getUsedInternetBytes()

        tvConnectionDuration.text = GoodbyeDpiEngine.formatDuration(durationSec)
        tvInternetUsed.text = GoodbyeDpiEngine.formatBytes(usedBytes)

        btnStart.alpha = if (running) 0.6f else 1.0f
        btnStop.alpha = if (running) 1.0f else 0.6f
    }
}
