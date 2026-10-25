package com.goodbyedpi.turkey

import android.content.Intent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityInstrumentedTest {

    @Before
    fun grantVpnAppOps() {
        try {
            InstrumentationRegistry.getInstrumentation().uiAutomation
                .executeShellCommand("appops set com.goodbyedpi.turkey ACTIVATE_VPN allow")
                .close()
        } catch (_: Throwable) {
        }
    }

    @Test
    fun testNativeJniEngineLoadedAndFunctionalOnDevice() {
        assertTrue("Native C GoodbyeDPI-Turkey library must be loaded", GoodbyeDpiEngine.isNativeLoaded())

        val fakeHello = GoodbyeDpiEngine.buildFakeClientHello("goodbyedpi.turkey.test")
        val sni = GoodbyeDpiEngine.extractSni(fakeHello)
        assertEquals("goodbyedpi.turkey.test", sni)

        val splitOffset = GoodbyeDpiEngine.calcTlsSplitOffset(fakeHello, fragBySni = true)
        assertTrue("TLS split offset must be before SNI", splitOffset > 2)
    }

    @Test
    fun testUiHasOnlyStartAndStopButtonsAndDisplaysDurationAndInternet() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val root = activity.findViewById<ViewGroup>(R.id.rootLayout)
                val buttons = mutableListOf<Button>()
                collectButtons(root, buttons)

                // Verify ONLY Start ("Başlat") and Stop ("Durdur") buttons exist in UI
                assertEquals("UI must have exactly 2 buttons (Başlat & Durdur)", 2, buttons.size)
                assertEquals("Başlat", activity.findViewById<Button>(R.id.btnStart).text.toString())
                assertEquals("Durdur", activity.findViewById<Button>(R.id.btnStop).text.toString())

                val tvDuration = activity.findViewById<TextView>(R.id.tvConnectionDuration)
                val tvInternet = activity.findViewById<TextView>(R.id.tvInternetUsed)
                assertEquals(View.VISIBLE, tvDuration.visibility)
                assertEquals(View.VISIBLE, tvInternet.visibility)

                // Click Start button
                activity.findViewById<Button>(R.id.btnStart).performClick()
            }

            Thread.sleep(1500)

            scenario.onActivity { activity ->
                activity.updateStatsUi()
                assertTrue("Service should be running after clicking Başlat", GoodbyeDpiVpnService.isServiceRunning())
                assertTrue("Used internet bytes should be > 0", GoodbyeDpiVpnService.getUsedInternetBytes() > 0L)

                val tvDuration = activity.findViewById<TextView>(R.id.tvConnectionDuration)
                val tvInternet = activity.findViewById<TextView>(R.id.tvInternetUsed)
                assertFalse("Duration should have incremented from 00:00:00", tvDuration.text.toString() == "00:00:00")
                assertFalse("Internet used should have incremented from 0 B", tvInternet.text.toString() == "0 B")

                // Click Stop button
                activity.findViewById<Button>(R.id.btnStop).performClick()
                assertFalse("Service should stop after clicking Durdur", GoodbyeDpiVpnService.isServiceRunning())
            }
        }
    }

    private fun collectButtons(view: View, out: MutableList<Button>) {
        if (view is Button && view.visibility == View.VISIBLE) {
            out.add(view)
        } else if (view is ViewGroup) {
            for (i in 0 until view.childCount) {
                collectButtons(view.getChildAt(i), out)
            }
        }
    }
}
