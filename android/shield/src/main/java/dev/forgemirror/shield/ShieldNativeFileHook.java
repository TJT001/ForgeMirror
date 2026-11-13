package dev.forgemirror.shield;

/** Installs libc-level file hooks so business native code cannot bypass the encrypted files. */
final class ShieldNativeFileHook {
    static {
        System.loadLibrary("shield_hook");
    }

    private ShieldNativeFileHook() {
    }

    static int configure(String dataDir, boolean enforce) {
        return nativeConfigure(dataDir, enforce);
    }

    static boolean installed() {
        return nativeInstalled();
    }

    private static native int nativeConfigure(String dataDir, boolean enforce);

    private static native boolean nativeInstalled();
}
