package dev.forgemirror.shield;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Debug;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    private static volatile ShieldPolicy policy;
    private static volatile ShieldRules rules;
    private static volatile byte[] fileKey;
    private static volatile boolean ruleScanStarted;
    private static final Map<String, ShieldSharedPreferences> PREFS = new HashMap<>();

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

            if ((config.key != null && !config.key.isEmpty())
                    || (config.authUrl != null && !config.authUrl.isEmpty())) {
                long started = SystemClock.elapsedRealtimeNanos();
                byte[] key;
                if (config.key != null && !config.key.isEmpty()) {
                    key = ShieldAssets.read(context, config.key);
                } else {
                    key = ShieldAuthClient.fetchContentKey(context, config);
                    Log.i(TAG, "content key obtained from dev authorization");
                }
                try {
                    policy = ShieldPolicy.load(context, config, key);
                } catch (Exception error) {
                    fail("policy load failed: " + error);
                    return state;
                }
                fileKey = ShieldPolicy.deriveFileKey(key, config.buildId);
                rules = ShieldRules.load(context, config, key);
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
            startRuleScan(context);
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

    static boolean protects(String relPath) {
        ShieldPolicy active = policy;
        return active != null && active.encrypts(relPath);
    }

    static byte[] fileKey() {
        return fileKey;
    }

    static SharedPreferences sharedPreferences(String name, Context base) {
        synchronized (PREFS) {
            ShieldSharedPreferences prefs = PREFS.get(name);
            if (prefs == null) {
                prefs = new ShieldSharedPreferences(
                        new File(base.getDataDir(), "shared_prefs/" + name + ".xml"),
                        fileKey);
                PREFS.put(name, prefs);
            }
            return prefs;
        }
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
            if (base == null) {
                return;
            }
            ShieldContextAdapter.adaptClassLoader(base, memory);
            Log.i(TAG, "activity context adapted: " + activity.getClass().getName());
        } catch (Throwable error) {
            Log.w(TAG, "activity context adaptation failed", error);
        }
    }

    private static void startRuleScan(Context context) {
        ShieldRules active = rules;
        if (active == null || ruleScanStarted) {
            return;
        }
        ruleScanStarted = true;
        Thread thread = new Thread(() -> {
            long started = SystemClock.elapsedRealtime();
            List<String> matches = active.scanApk(context.getApplicationInfo().sourceDir);
            Log.i(TAG, "rule scan done matches=" + matches
                    + " ms=" + (SystemClock.elapsedRealtime() - started));
        }, "shield-rule-scan");
        thread.setDaemon(true);
        thread.start();
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
