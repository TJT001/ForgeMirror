package dev.forgemirror.shield;

import android.os.Build;

import java.util.Arrays;

/** P1-C runtime environment probe; ART adapters are added only on real failures. */
public final class ShieldArt {
    private ShieldArt() {
    }

    public static String describe() {
        return "sdk=" + Build.VERSION.SDK_INT + " abis=" + Arrays.toString(Build.SUPPORTED_ABIS);
    }
}
