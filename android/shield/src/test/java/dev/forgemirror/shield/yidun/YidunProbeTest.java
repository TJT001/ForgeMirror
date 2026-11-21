package dev.forgemirror.shield.yidun;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class YidunProbeTest {
    private static List<String> list(String... values) {
        return Arrays.asList(values);
    }

    private static YidunSignatures signatures() {
        return new YidunSignatures(
                "NetEase Yidun", "libnesec.so", "sha256", "docs/research/libnesec_易盾加固还原.md",
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
                list("com.bluestacks.", "com.microvirt."));
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
    public void allRulesCarryYidunPrefix() {
        List<String> rules = list(YidunProbe.RULE_ROOT, YidunProbe.RULE_MOUNT,
                YidunProbe.RULE_DEBUG, YidunProbe.RULE_HOOK, YidunProbe.RULE_XPOSED,
                YidunProbe.RULE_INJECTION, YidunProbe.RULE_EMULATOR,
                YidunProbe.RULE_LD_PRELOAD);
        for (String rule : rules) {
            assertTrue(rule.startsWith("yidun_"));
        }
        assertTrue(Collections.frequency(rules, YidunProbe.RULE_ROOT) == 1);
    }
}
