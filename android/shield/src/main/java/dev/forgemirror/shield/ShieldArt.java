package dev.forgemirror.shield;

import android.os.Build;

/** P1-C4 runtime probe with deliberately empty ART adapters. */
public final class ShieldArt {
    interface Adapter {
        String name();

        /** Filled only when a measured ART failure requires class verification. */
        boolean verifyClass(ClassLoader loader, String name);
    }

    private static final Adapter LEGACY = new Adapter() {
        @Override
        public String name() {
            return "art-26-28";
        }

        @Override
        public boolean verifyClass(ClassLoader loader, String name) {
            return true;
        }
    };

    private static final Adapter MODERN = new Adapter() {
        @Override
        public String name() {
            return "art-29+";
        }

        @Override
        public boolean verifyClass(ClassLoader loader, String name) {
            return true;
        }
    };

    private ShieldArt() {
    }

    static Adapter adapter() {
        return Build.VERSION.SDK_INT >= 29 ? MODERN : LEGACY;
    }

    static boolean verifyClass(ClassLoader loader, String name) {
        return adapter().verifyClass(loader, name);
    }

    public static String describe() {
        return "sdk=" + Build.VERSION.SDK_INT
                + " release=" + Build.VERSION.RELEASE
                + " vm=" + System.getProperty("java.vm.version", "?")
                + " abis=" + String.join(",", Build.SUPPORTED_ABIS == null
                        ? new String[0] : Build.SUPPORTED_ABIS)
                + " adapter=" + adapter().name();
    }
}
