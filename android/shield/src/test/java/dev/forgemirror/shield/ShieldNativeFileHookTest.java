package dev.forgemirror.shield;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

public final class ShieldNativeFileHookTest {
    @Test
    public void missingNativeLibraryDegradesGracefully() {
        assertEquals(-2, ShieldNativeFileHook.configure(
                "/tmp", true, new String[0]));
        assertFalse(ShieldNativeFileHook.installed());
        ShieldNativeFileHook.setBlockMode(2);
    }
}
