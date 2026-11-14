package dev.forgemirror.shield;

/** Installs libc-level file hooks so business native code cannot bypass the encrypted files. */
final class ShieldNativeFileHook {
    static {
        System.loadLibrary("shield_hook");
    }

    private ShieldNativeFileHook() {
    }

    static int configure(String dataDir, boolean enforce, String[] nativeLibs) {
        return nativeConfigure(dataDir, enforce, nativeLibs);
    }

    static boolean installed() {
        return nativeInstalled();
    }

    static void setBlockMode(int mode) {
        nativeSetBlockMode(mode);
    }

    private static native int nativeConfigure(String dataDir, boolean enforce,
                                               String[] nativeLibs);

    private static native boolean nativeInstalled();

    private static native void nativeSetBlockMode(int mode);
}
