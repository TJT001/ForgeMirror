package dev.forgemirror.shield;

/** P0 ABI probe only; does not decrypt or protect application code. */
public final class ShieldRuntime {
    static { System.loadLibrary("shield_boot"); }
    private ShieldRuntime() {}
    public static native int abiVersion();
    public static native String describe();
}
