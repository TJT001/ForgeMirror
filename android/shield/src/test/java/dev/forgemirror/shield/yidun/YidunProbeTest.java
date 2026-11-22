package dev.forgemirror.shield.yidun;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class YidunProbeTest {
    private static List<String> list(String... values) {
        return Arrays.asList(values);
    }

    private static YidunSignatures signatures() {
        return new YidunSignatures(
                "NetEase Yidun", "libnesec.so", "sha256",
                "docs/research/libnesec_易盾加固还原.md", "2026-11-21", false,
                list("/system/bin/su", "/system/xbin/su"),
                list("magisk", "system_root"),
                list("TracerPid:", "State:"), "(zombie)",
                list("NativeBridgeError"),
                list("XposedBridge", "app_process64_xposed", "libexp824", "frida-agent-"),
                list("de/robv/android/xposed/XposedBridge",
                        "me/weishu/exposed/ExposedBridge",
                        "com/swift/sandhook/SandHook"),
                list("user.xposed.system"),
                list("libexp824", "inject.dex"),
                list("libriru_", "libsubstrate"),
                list("/system/bin/nox-prop", "/system/bin/ldinit"),
                list("vbox86p", "genymotion"),
                list("init.svc.ldinit", "ro.genymotion.version"),
                list("com.bluestacks.", "com.microvirt."),
                list("VMOS_MANAGER_SERVICE"),
                list("dex\n035\0", "cdex001\0"),
                list("dex2oat"));
    }

    @Test
    public void rootPathAndMountClassification() {
        YidunSignatures signatures = signatures();
        assertTrue(YidunProbe.matchSuPath("/system/bin/su", signatures));
        assertFalse(YidunProbe.matchSuPath("/system/bin/sh", signatures));
        assertTrue(YidunProbe.matchMountLine(
                "magisk /sbin tmpfs ro,seclabel 0 0", signatures));
        assertTrue(YidunProbe.matchMountLine(
                "/dev/block/dm-1 /system_root ext4 ro 0 0", signatures));
        assertFalse(YidunProbe.matchMountLine(
                "/dev/block/dm-1 /data ext4 rw 0 0", signatures));
        assertEquals("magisk", YidunProbe.matchMountMarker(
                "magisk /system/lib tmpfs ro 0 0", signatures));
        assertEquals("system_root", YidunProbe.matchMountMarker(
                "/dev/block/dm-1 /system_root ext4 ro 0 0", signatures));
        assertNull(YidunProbe.matchMountMarker(
                "/dev/block/dm-1 /data ext4 rw 0 0", signatures));
    }

    @Test
    public void emulatorClassification() {
        YidunSignatures signatures = signatures();
        assertTrue(YidunProbe.matchEmulatorPath("/system/bin/nox-prop", signatures));
        assertFalse(YidunProbe.matchEmulatorPath("/system/bin/sh", signatures));
        assertTrue(YidunProbe.matchEmulatorBuild(
                "generic/vbox86p/vbox86p:10/Q/1:userdebug/test-keys", signatures));
        assertFalse(YidunProbe.matchEmulatorBuild(
                "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys",
                signatures));
        assertTrue(YidunProbe.matchEmulatorProperty("init.svc.ldinit", signatures));
        assertFalse(YidunProbe.matchEmulatorProperty("ro.build.version.sdk", signatures));
        assertTrue(YidunProbe.matchCloudPhonePackage(
                "com.bluestacks.home", signatures));
        assertFalse(YidunProbe.matchCloudPhonePackage(
                "dev.forgemirror.demo", signatures));
        assertTrue(YidunProbe.matchCloudService("VMOS_MANAGER_SERVICE", signatures));
        assertFalse(YidunProbe.matchCloudService("user.xposed.system", signatures));
    }

    @Test
    public void mapsAndElfClassification() throws Exception {
        byte[] aarch64 = new byte[20];
        aarch64[0] = 0x7f;
        aarch64[1] = 'E';
        aarch64[2] = 'L';
        aarch64[3] = 'F';
        aarch64[4] = 2;
        aarch64[5] = 1;
        aarch64[18] = (byte) 0xB7;
        assertEquals(0xB7, YidunProbe.elfMachine(aarch64));
        assertTrue(YidunProbe.isNativeElfMachine(0xB7));
        assertTrue(YidunProbe.isNativeElfMachine(0x28));
        assertTrue(YidunProbe.isNativeElfMachine(0x3E));
        assertTrue(YidunProbe.isNativeElfMachine(0x03));
        assertFalse(YidunProbe.isNativeElfMachine(0x14));
        byte[] bigEndian = aarch64.clone();
        bigEndian[5] = 2;
        bigEndian[18] = 0;
        bigEndian[19] = (byte) 0xB7;
        assertEquals(0xB7, YidunProbe.elfMachine(bigEndian));
        byte[] badMagic = aarch64.clone();
        badMagic[0] = 0;
        assertEquals(-1, YidunProbe.elfMachine(badMagic));
        assertEquals(0xB7, YidunProbe.elfMachine(tempFile(aarch64)));

        assertTrue(YidunProbe.isReadableMapLine(
                "7f0000-7f1000 r-xp 00000000 fd:00 1 /data/app/libfoo.so"));
        assertFalse(YidunProbe.isReadableMapLine(
                "7f0000-7f1000 ---p 00000000 fd:00 1 /data/app/libfoo.so"));
        assertFalse(YidunProbe.isReadableMapLine("7f0000-7f1000 r-xp 00000000"));
        assertEquals("/data/app/libfoo.so",
                YidunProbe.mapsPath("/data/app/libfoo.so (deleted)"));
        assertNull(YidunProbe.mapsPath(
                "/data/app/base.apk!lib/arm64-v8a/libfoo.so"));
    }

    @Test
    public void dexMagicClassification() throws Exception {
        YidunSignatures signatures = signatures();
        assertTrue(YidunProbe.isStandardDexMagic("dex\n035\0", signatures));
        assertTrue(YidunProbe.isStandardDexMagic("cdex001\0", signatures));
        assertFalse(YidunProbe.isStandardDexMagic("dex\n099\0", signatures));
        assertFalse(YidunProbe.isStandardDexMagic(null, signatures));

        File dex = tempFile("dex\n035\0".getBytes(StandardCharsets.ISO_8859_1));
        assertEquals("dex\n035\0", YidunProbe.dexMagic(dex));
        assertEquals("dex\\n035\\0", YidunProbe.printable(YidunProbe.dexMagic(dex)));
        assertEquals("unreadable", YidunProbe.printable(null));
    }

    private static File tempFile(byte[] data) throws Exception {
        File file = File.createTempFile("forgemirror-yidun", ".bin");
        file.deleteOnExit();
        try (java.io.FileOutputStream output = new java.io.FileOutputStream(file)) {
            output.write(data);
        }
        return file;
    }

    @Test
    public void hookClassification() {
        YidunSignatures signatures = signatures();
        assertEquals(YidunProbe.RULE_INJECTION, YidunProbe.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/local/tmp/libexp824.so",
                signatures));
        assertEquals(YidunProbe.RULE_XPOSED, YidunProbe.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/adb/app_process64_xposed",
                signatures));
        assertEquals(YidunProbe.RULE_HOOK, YidunProbe.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/local/tmp/frida-agent-64.so",
                signatures));
        assertNull(YidunProbe.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/app/libshield_hook.so",
                signatures));
        assertEquals(YidunProbe.RULE_XPOSED, YidunProbe.classifyHookClass(
                "me.weishu.exposed.ExposedBridge", signatures));
        assertEquals(YidunProbe.RULE_HOOK, YidunProbe.classifyHookClass(
                "com.swift.sandhook.SandHook", signatures));
        assertNull(YidunProbe.classifyHookClass(
                "java.lang.String", signatures));
        assertTrue(YidunProbe.matchLdPreload(
                "/data/local/tmp/libfoo.so /data/local/tmp/libriru_x.so", signatures));
        assertFalse(YidunProbe.matchLdPreload(
                "/data/local/tmp/libfoo.so", signatures));
    }

    @Test
    public void debugClassification() {
        YidunSignatures signatures = signatures();
        assertEquals(123, YidunProbe.tracerPid("TracerPid:\t123"));
        assertEquals(-1, YidunProbe.tracerPid("State:\tS (sleeping)"));
        assertTrue(YidunProbe.isZombie("State:\tZ (zombie)", signatures));
        assertFalse(YidunProbe.isZombie("State:\tS (sleeping)", signatures));
    }

    @Test
    public void platformChecks() {
        assertTrue(YidunProbe.isUsbDebugging(1));
        assertFalse(YidunProbe.isUsbDebugging(0));

        assertTrue(YidunProbe.isMockLocationSetting("com.lexa.fakegps"));
        assertFalse(YidunProbe.isMockLocationSetting("0"));
        assertFalse(YidunProbe.isMockLocationSetting("null"));
        assertFalse(YidunProbe.isMockLocationSetting(""));
        assertFalse(YidunProbe.isMockLocationSetting(null));
        assertTrue(YidunProbe.isKnownMockLocationPackage("com.lexa.fakegps"));
        assertFalse(YidunProbe.isKnownMockLocationPackage(
                "dev.forgemirror.demo"));

        assertNull(YidunProbe.classifyRom(
                "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys",
                "google", "redfin", "redfin", "Google"));
        assertEquals("Build.FINGERPRINT.device=redfin,Build.DEVICE=sunfish",
                YidunProbe.classifyRom(
                        "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys",
                        "google", "sunfish", "sunfish", "Google"));
        assertEquals("Build.FINGERPRINT.brand=google,Build.BRAND=samsung",
                YidunProbe.classifyRom(
                        "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys",
                        "samsung", "redfin", "redfin", "Samsung"));
        assertEquals("Build.FINGERPRINT=malformed", YidunProbe.classifyRom(
                "bad", "google", "redfin", "redfin", "Google"));
        assertEquals("Build.field_unknown=BRAND:google,DEVICE:redfin,PRODUCT:redfin,MANUFACTURER:",
                YidunProbe.classifyRom(
                        "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys",
                        "google", "redfin", "redfin", ""));
    }

    @Test
    public void candidatePlatformClassifiers() {
        assertTrue(YidunProbe.hasProxyConfig("10.0.2.2", null, null, null));
        assertTrue(YidunProbe.hasProxyConfig(null, null, null, "tun0"));
        assertFalse(YidunProbe.hasProxyConfig(null, null, null, "wlan0"));
        assertFalse(YidunProbe.hasProxyConfig(null, null, ":0", null));
        assertFalse(YidunProbe.hasProxyConfig(null, null, "0", null));
        assertFalse(YidunProbe.hasProxyConfig(null, null, "null", null));
        assertTrue(YidunProbe.hasCaptureCaMarker("CN=mitmproxy, O=mitmproxy"));
        assertFalse(YidunProbe.hasCaptureCaMarker("CN=Let's Encrypt"));

        assertEquals(Arrays.asList("com.foo", "com.bar"),
                YidunProbe.accessibilityPackages(
                        "com.foo/.Svc:com.bar/.Svc"));
        assertTrue(YidunProbe.accessibilityPackages(null).isEmpty());
        assertTrue(YidunProbe.isKnownAutomationPackage("org.autojs.autojs"));
        assertFalse(YidunProbe.isKnownAutomationPackage(
                "com.android.talkback"));
        assertTrue(YidunProbe.isKnownClonePackage("com.lbe.parallel"));
        assertTrue(YidunProbe.isKnownCapturePackage("com.pcapdroid"));
        assertTrue(YidunProbe.isKnownScreenPackage("com.mobizen"));

        assertNull(YidunProbe.classifyClone(
                1000, 1000, "/data/a", "/data/a", false, false, false));
        assertEquals("uid:mismatch my=1000,expected=1001",
                YidunProbe.classifyClone(
                        1000, 1001, "/data/a", "/data/a", false, false, false));
        assertEquals("dataDir:mismatch my=/a,expected=/b",
                YidunProbe.classifyClone(
                        1000, 1000, "/a", "/b", false, false, false));
        assertNull(YidunProbe.classifyClone(
                1000, 1001, "/a", "/b", true, false, false));
        assertEquals("package+path", YidunProbe.classifyClone(
                1000, 1000, "/a", "/a", false, true, true));

        assertFalse(signatures().platformEnabled);
        assertTrue(signatures().withPlatformEnabled(true).platformEnabled);
    }

    @Test
    public void allRulesCarryYidunPrefix() {
        List<String> rules = list(YidunProbe.RULE_ROOT, YidunProbe.RULE_MOUNT,
                YidunProbe.RULE_DEBUG, YidunProbe.RULE_HOOK, YidunProbe.RULE_XPOSED,
                YidunProbe.RULE_INJECTION, YidunProbe.RULE_EMULATOR,
                YidunProbe.RULE_LD_PRELOAD, YidunProbe.RULE_DEX,
                YidunProbe.RULE_USB_DEBUG, YidunProbe.RULE_VPN,
                YidunProbe.RULE_MOCK_LOCATION, YidunProbe.RULE_ROM);
        for (String rule : rules) {
            assertTrue(rule.startsWith("yidun_"));
        }
        assertTrue(Collections.frequency(rules, YidunProbe.RULE_ROOT) == 1);

        List<String> candidateRules = list(YidunProbe.RULE_PROXY,
                YidunProbe.RULE_PACKET_CAPTURE, YidunProbe.RULE_CLONE,
                YidunProbe.RULE_AUTOTAP, YidunProbe.RULE_SCREEN_SHARE);
        for (String rule : candidateRules) {
            assertTrue(rule.startsWith("env_"));
        }
    }
}
