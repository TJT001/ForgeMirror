package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

/**
 * P1-B stub runtime: verify the signed manifest, check protected artifacts, and
 * bring up the native Core. DEX decryption/loading is P1-C.
 */
public final class ShieldRuntime {
    public static final int STATE_UNINITIALIZED = 0;
    public static final int STATE_VERIFIED = 1;
    public static final int STATE_KEY_READY = 2;
    public static final int STATE_DEX_READY = 3;
    public static final int STATE_APP_ATTACHED = 4;
    public static final int STATE_RUNNING = 5;
    public static final int STATE_RECOVERY = 6;

    private static final int FM_OK = 0;
    private static final int FM_RECOVERY_REQUIRED = 8;
    private static final String TAG = "ShieldRuntime";

    private static volatile int state = STATE_UNINITIALIZED;
    private static volatile String failure = "";
    private static volatile ShieldConfig config;

    static {
        System.loadLibrary("shield_boot");
    }

    private ShieldRuntime() {
    }

    public static synchronized int bootstrap(Context context) {
        if (context == null) {
            fail("bootstrap without context");
            return state;
        }
        if (state == STATE_RECOVERY || state >= STATE_DEX_READY) {
            return state;
        }

        try {
            if (config == null) {
                config = ShieldConfig.load(context);
            }
            if (state < STATE_VERIFIED) {
                ShieldIntegrity.verify(context, config);
                state = STATE_VERIFIED;
            }

            // P1-B uses a local developer key path; key service is P2.
            state = STATE_KEY_READY;

            int status = nativeBootstrap();
            if (status == FM_RECOVERY_REQUIRED) {
                try {
                    System.loadLibrary("shield_core");
                    status = nativeBootstrap();
                } catch (UnsatisfiedLinkError error) {
                    fail("core load failed: " + error);
                    return state;
                }
            }
            if (status != FM_OK) {
                fail("native boot status " + status);
                return state;
            }

            state = STATE_DEX_READY;
            state = STATE_APP_ATTACHED;
            Log.i(TAG, "bootstrap ok state=" + state);
            return state;
        } catch (Throwable error) {
            fail("bootstrap failed: " + error);
            return state;
        }
    }

    private static void fail(String reason) {
        failure = reason;
        state = STATE_RECOVERY;
        Log.e(TAG, reason);
    }

    public static int getState() {
        return state;
    }

    public static boolean isRecovery() {
        return state == STATE_RECOVERY;
    }

    public static String getFailure() {
        return failure;
    }

    public static ShieldConfig getConfig() {
        return config;
    }

    public static void markRunning() {
        if (state == STATE_APP_ATTACHED) {
            state = STATE_RUNNING;
        }
    }

    private static native int nativeBootstrap();

    public static native int abiVersion();

    public static native String describe();
}
