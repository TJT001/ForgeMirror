package dev.forgemirror.shield;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Debug;
import android.os.SystemClock;
import android.util.Log;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;

/**
 * Shield runtime: verify the signed manifest, decrypt the FDX2 container into
 * memory, and install the business class loader. See P1-B/C/C+ evidence.
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
    private static volatile ClassLoader memoryLoader;
    private static volatile byte[][] dexBuffers;
    private static volatile int dexCount;
    private static volatile long decryptMs;

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

            if (config.key != null && !config.key.isEmpty()) {
                long started = SystemClock.elapsedRealtimeNanos();
                byte[] key = ShieldAssets.read(context, config.key);
                byte[] container = ShieldAssets.read(context, config.container);
                byte[][] dex = ShieldContainer.open(container, key);
                ByteBuffer[] buffers = new ByteBuffer[dex.length];
                for (int index = 0; index < dex.length; index++) {
                    buffers[index] = ByteBuffer.wrap(dex[index]);
                }
                memoryLoader = new ShieldClassLoader(
                        buffers, ShieldRuntime.class.getClassLoader(), context);
                dexBuffers = dex;
                dexCount = dex.length;
                decryptMs = (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000L;
                Log.i(TAG, "dex loaded count=" + dexCount + " decryptMs=" + decryptMs
                        + " pssKb=" + pssKb() + " " + ShieldArt.describe());
            }

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

    public static ClassLoader getClassLoader() {
        return memoryLoader;
    }

    public static int getDexCount() {
        return dexCount;
    }

    public static long getDecryptMs() {
        return decryptMs;
    }

    private static long pssKb() {
        try {
            return Debug.getPss();
        } catch (Throwable ignored) {
            return -1;
        }
    }

    static void adaptActivity(Activity activity) {
        ClassLoader memory = memoryLoader;
        if (activity == null || memory == null) {
            return;
        }
        try {
            Context base = activity.getBaseContext();
            if (base == null || base instanceof ShieldContextWrapper) {
                return;
            }
            ShieldContextWrapper wrapper = new ShieldContextWrapper(base, memory);
            Field baseField = ContextWrapper.class.getDeclaredField("mBase");
            baseField.setAccessible(true);
            baseField.set(activity, wrapper);
            Log.i(TAG, "activity context adapted: " + activity.getClass().getName());
        } catch (Throwable error) {
            Log.w(TAG, "activity context adaptation failed", error);
        }
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
