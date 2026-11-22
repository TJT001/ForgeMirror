package dev.forgemirror.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import dev.forgemirror.shield.yidun.YidunProbe;
import dev.forgemirror.shield.yidun.YidunSignatures;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Device-side check for the Yidun-derived probes. The assertion is
 * environment-aware: a physical device must not report emulator findings,
 * while an emulator must report at least one. Hook, Xposed and injection
 * findings must stay empty on both unless those tools are actually present.
 */
@RunWith(AndroidJUnit4.class)
public class YidunProbeDeviceTest {
    private static final String TAG = "YidunProbeDevice";

    @Test
    public void probeMatchesDeviceTypeWithoutHookFalsePositives() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        YidunSignatures signatures = YidunSignatures.load(context);
        assertFalse("Yidun signature asset missing from APK", signatures.isEmpty());
        boolean emulator = isEmulator();
        Log.i(TAG, "environment emulator=" + emulator
                + " fingerprint=" + Build.FINGERPRINT
                + " hardware=" + Build.HARDWARE + " product=" + Build.PRODUCT);
        Log.i(TAG, "signatures source=" + signatures.vendor + "/" + signatures.library
                + " sample=" + signatures.sampleSha256);

        long started = android.os.SystemClock.elapsedRealtime();
        List<YidunProbe.Finding> findings = new YidunProbe(signatures).scan(context);
        Log.i(TAG, "probe findings=" + findings.size()
                + " elapsedMs=" + (android.os.SystemClock.elapsedRealtime() - started));
        List<String> emulatorFindings = new ArrayList<>();
        List<String> dexFindings = new ArrayList<>();
        List<String> unexpected = new ArrayList<>();
        for (YidunProbe.Finding finding : findings) {
            Log.i(TAG, finding.ruleId + " kind=" + finding.kind
                    + " confidence=" + finding.confidence
                    + " evidence=" + finding.evidence);
            if ("emulator".equals(finding.kind)) {
                emulatorFindings.add(finding.ruleId + ":" + finding.evidence);
            } else if ("dex".equals(finding.kind)) {
                dexFindings.add(finding.ruleId + ":" + finding.evidence);
            } else if ("hook".equals(finding.kind) || "xposed".equals(finding.kind)
                    || "injection".equals(finding.kind)
                    || "vpn".equals(finding.kind)
                    || "location".equals(finding.kind)
                    || "rom".equals(finding.kind)) {
                // Test devices have no active VPN, mock-location app/setting,
                // or custom ROM; these would be false positives here.
                unexpected.add(finding.ruleId + ":" + finding.evidence);
            } else if ("usb".equals(finding.kind)) {
                Log.i(TAG, "usb debugging detected (expected with adb enabled)");
            }
        }
        for (String dex : dexFindings) {
            // Standard DEX in code_cache is reported but tolerated; unknown magic
            // or a dex2oat mapping is treated as a false positive here.
            if (!dex.contains("magic=dex\\n") && !dex.contains("magic=cdex")) {
                unexpected.add(dex);
            }
        }
        assertTrue("unexpected hook/xposed/injection/vpn/location/rom/dex findings: "
                        + unexpected, unexpected.isEmpty());
        if (emulator) {
            assertFalse("emulator not detected: " + findings, emulatorFindings.isEmpty());
        } else {
            assertTrue("emulator false positive: " + emulatorFindings,
                    emulatorFindings.isEmpty());
        }
    }

    @Test
    public void pkr1PayloadParsesWithProvenance() throws Exception {
        String json = "{\"schema\":\"forgemirror.yidun-signatures/1\","
                + "\"source\":{\"vendor\":\"NetEase Yidun\","
                + "\"library\":\"libnesec.so\","
                + "\"sample_sha256\":\"8ff576e1cc403f0d6173bee361dabc362be6319f4b71ceb375834600a50005ff\","
                + "\"evidence\":\"docs/research/libnesec_易盾加固还原.md\","
                + "\"captured\":\"device-test\"},"
                + "\"root\":{\"su_paths\":[\"/system/bin/su\"]},"
                + "\"emulator\":{\"cloud_services\":[\"VMOS_MANAGER_SERVICE\"]},"
                + "\"dex\":{\"standard_magic\":[\"dex\\n035\\u0000\"],"
                + "\"dex2oat_markers\":[\"dex2oat\"]}}";
        YidunSignatures parsed = YidunSignatures.parse(json);
        assertEquals("NetEase Yidun", parsed.vendor);
        assertEquals("device-test", parsed.captured);
        assertTrue(parsed.suPaths.contains("/system/bin/su"));
        assertTrue(parsed.cloudServices.contains("VMOS_MANAGER_SERVICE"));
        assertTrue(parsed.dexStandardMagic.contains("dex\n035\0"));
    }

    @Test(expected = SecurityException.class)
    public void pkr1PayloadWithoutSourceIsRejected() throws Exception {
        YidunSignatures.parse("{\"schema\":\"forgemirror.yidun-signatures/1\"}");
    }

    private static boolean isEmulator() {
        String fingerprint = lower(Build.FINGERPRINT);
        String hardware = lower(Build.HARDWARE);
        String product = lower(Build.PRODUCT);
        return fingerprint.contains("generic")
                || fingerprint.contains("emulator")
                || hardware.contains("goldfish")
                || hardware.contains("ranchu")
                || product.contains("sdk")
                || product.contains("vbox");
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.US);
    }
}
