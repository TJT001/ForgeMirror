package dev.forgemirror.shield;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class ShieldDetectTest {
    @Test
    public void mapsClassification() {
        assertEquals("env_frida", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/local/tmp/frida-agent-64.so"));
        assertEquals("env_xposed", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/adb/modules/lsposed/lib.so"));
        assertEquals("env_injection", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/adb/modules/zygisk/libzygisk.so"));
        assertEquals("env_unpacker", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/local/tmp/youpk.so"));
        assertEquals("env_hook", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/local/tmp/libbhook.so"));
        assertEquals("env_xposed", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/adb/modules/dexposed/lib.so"));
        assertEquals("env_injection", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/adb/modules/adbi/lib.so"));
        assertEquals("env_unpacker", ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/local/tmp/fupk3.so"));
        assertNull(ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/app/libshield_hook.so"));
        assertNull(ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /data/app/com.example/libc++_shared.so"));
        assertNull(ShieldDetect.classifyMapsLine(
                "7f0000 r-xp 00000000 fd:00 1 /system/lib64/libc.so"));
    }

    @Test
    public void pathAndPortClassification() {
        assertEquals("env_frida", ShieldDetect.classifyKnownPath(
                "/data/local/tmp/frida-server"));
        assertEquals("env_injection", ShieldDetect.classifyKnownPath(
                "/data/adb/modules/zygisk_zygisk"));
        assertNull(ShieldDetect.classifyKnownPath("/data/local/tmp/demo"));
        assertEquals("env_frida", ShieldDetect.classifyTcpLine(
                "0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000"));
        assertNull(ShieldDetect.classifyTcpLine(
                "1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000"));
    }

    @Test
    public void threadClassification() {
        assertEquals("env_frida", ShieldDetect.classifyThread("gum-js-loop"));
        assertEquals("env_frida", ShieldDetect.classifyThread("pool-frida"));
        assertNull(ShieldDetect.classifyThread("RenderThread"));
    }

    @Test
    public void buildClassification() {
        assertEquals("env_emulator", ShieldDetect.classifyBuild(
                "google/sdk_gphone64_arm64/emu64a:13/TQ1A/1:userdebug/test-keys",
                "sdk_gphone64_arm64", "ranchu", "sdk_gphone64_arm64"));
        assertEquals("env_emulator", ShieldDetect.classifyBuild(
                "generic/vbox86p/vbox86p:10/Q/1:userdebug/test-keys",
                "vbox86p", "vbox86p", "vbox86p"));
        assertNull(ShieldDetect.classifyBuild(
                "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys",
                "Pixel 5", "redfin", "redfin"));
    }
}
