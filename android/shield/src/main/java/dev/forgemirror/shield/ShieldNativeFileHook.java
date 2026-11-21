package dev.forgemirror.shield;

/** Installs libc-level file hooks so business native code cannot bypass the encrypted files. */
final class ShieldNativeFileHook {
    private static final boolean LOADED;

    static {
        boolean loaded = false;
        try {
            System.loadLibrary("shield_hook");
            loaded = true;
        } catch (Throwable error) {
            android.util.Log.w("ShieldNativeFileHook",
                    "native hooks unavailable on this ABI: " + error);
        }
        LOADED = loaded;
    }

    private ShieldNativeFileHook() {
    }

    static int configure(String dataDir, boolean enforce, String[] nativeLibs) {
        return LOADED ? nativeConfigure(dataDir, enforce, nativeLibs) : -2;
    }

    static boolean installed() {
        return LOADED && nativeInstalled();
    }

    static void setBlockMode(int mode) {
        if (LOADED) {
            nativeSetBlockMode(mode);
        }
    }

    private static native int nativeConfigure(String dataDir, boolean enforce,
                                               String[] nativeLibs);

    private static native boolean nativeInstalled();

    private static native void nativeSetBlockMode(int mode);
}
