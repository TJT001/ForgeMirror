package dev.forgemirror.shield;

import java.util.Arrays;
import java.util.List;

/** JNI bridge to the bundled YARA 4.5.4 engine. */
final class ShieldYara implements AutoCloseable {
    private static final String TAG = "ShieldYara";

    static {
        System.loadLibrary("shield_yara");
    }

    private long handle;

    ShieldYara(String source) {
        if (source == null || source.isEmpty()) {
            throw new IllegalArgumentException("empty YARA source");
        }
        handle = nativeCompile(source);
        if (handle == 0) {
            throw new IllegalArgumentException("YARA compile failed");
        }
    }

    List<String> scan(byte[] data) {
        if (handle == 0) {
            throw new IllegalStateException("YARA rules are closed");
        }
        String[] matches = nativeScan(handle, data);
        return matches == null ? List.of() : Arrays.asList(matches);
    }

    @Override
    public synchronized void close() {
        if (handle != 0) {
            nativeDestroy(handle);
            handle = 0;
        }
    }

    private static native long nativeCompile(String source);

    private static native String[] nativeScan(long handle, byte[] data);

    private static native void nativeDestroy(long handle);
}
