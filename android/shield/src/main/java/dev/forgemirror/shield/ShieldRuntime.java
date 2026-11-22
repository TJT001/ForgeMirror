package dev.forgemirror.shield;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Debug;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONObject;

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
    private static volatile byte[] nativeKey;
    private static volatile boolean ruleScanStarted;
    private static volatile int ruleMatchCount;
    private static final Map<String, ShieldSharedPreferences> PREFS = new HashMap<>();

    static {
        System.loadLibrary("shield_boot");
    }

    private ShieldRuntime() {
    }

    public static synchronized int bootstrap(Context context) {
        ShieldNativeLoader.cleanup(context);
        ShieldMetrics.start();
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
            byte[] buildId = ShieldPolicy.uuidBytes(config.buildId);
            boolean vaultReady = false;

            if ((config.key != null && !config.key.isEmpty())
                    || (config.authUrl != null && !config.authUrl.isEmpty())) {
                long started = SystemClock.elapsedRealtimeNanos();
                if (config.key != null && !config.key.isEmpty()) {
                    byte[] blob = ShieldAssets.read(context, config.key);
                    if (ShieldKeyVault.isWrapped(blob)) {
                        long vaultStarted = SystemClock.elapsedRealtimeNanos();
                        byte[] table = ShieldAssets.read(
                                context, ShieldKeyVault.TABLE_ASSET);
                        ShieldKeyVault.installWrapped(blob, table);
                        Log.i(TAG, "content key unwrapped in native white-box vault ms="
                                + (SystemClock.elapsedRealtimeNanos() - vaultStarted) / 1_000_000L);
                    } else {
                        ShieldKeyVault.installRaw(blob);
                    }
                } else {
                    byte[] key = ShieldAuthClient.fetchContentKey(context, config);
                    try {
                        ShieldKeyVault.installRaw(key);
                    } finally {
                        java.util.Arrays.fill(key, (byte) 0);
                    }
                    Log.i(TAG, "content key obtained from dev authorization");
                }
                vaultReady = true;
                try {
                    policy = ShieldPolicy.load(context, config, buildId);
                } catch (Exception error) {
                    fail("policy load failed: " + error);
                    return state;
                }
                fileKey = ShieldKeyVault.derive(ShieldKeyVault.DERIVE_FILE, buildId);
                nativeKey = ShieldKeyVault.derive(ShieldKeyVault.DERIVE_NATIVE, buildId);
                // Load rules before native file hooks so the provenance log is
                // visible even when the hooks intercept logging writes.
                rules = ShieldRules.load(context, config, buildId);
                ShieldDetect.setYidunSignatures(
                        rules == null ? null : rules.yidunSignatures());
                ShieldNativeIo.configure(context, config.maxNativeFileMb);
                try {
                    int hookStatus = ShieldNativeFileHook.configure(
                            context.getApplicationInfo().dataDir, true,
                            ShieldNativeLoader.encryptedLibraries(context));
                    Log.i(TAG, "native file hooks status=" + hookStatus);
                } catch (Throwable error) {
                    Log.w(TAG, "native file hooks unavailable: " + error);
                }
                ShieldEvents.init(context, config, fileKey);
                ShieldDetectionBridge.register(context);
                ShieldDetect.start(context, config);
                ShieldRuleUpdater.start(context, config, buildId);
                ShieldFileWatch.start(context, config);
                ShieldSelfCheck.start(context, config);
                byte[] container = ShieldAssets.read(context, config.container);
                long containerStarted = SystemClock.elapsedRealtimeNanos();
                byte[][] dex = ShieldKeyVault.openContainer(container);
                Log.i(TAG, "native container open ms="
                        + (SystemClock.elapsedRealtimeNanos() - containerStarted) / 1_000_000L);
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

            ParcelFileDescriptor coreDescriptor = null;
            if (config.core != null && !config.core.isEmpty() && vaultReady) {
                try {
                    coreDescriptor = ShieldCoreLoader.open(context, config, buildId);
                    Log.i(TAG, "encrypted core opened fd=" + coreDescriptor.getFd());
                } catch (Throwable error) {
                    Log.w(TAG, "encrypted core unavailable: " + error);
                }
            }
            int status = coreDescriptor != null
                    ? nativeBootstrapWithCore(coreDescriptor.getFd())
                    : nativeBootstrap();
            if (coreDescriptor != null) {
                try {
                    coreDescriptor.close();
                } catch (Exception ignored) {
                    // The linker has mapped the core by now.
                }
            }
            if (status == FM_RECOVERY_REQUIRED
                    && (config.core == null || config.core.isEmpty())) {
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
            ShieldMetrics.bootstrapDone();
            Log.i(TAG, "bootstrap ok state=" + state + " "
                    + ShieldMetrics.describe());
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

    static native long nativeLoadInMemory(byte[] elf, String name, boolean global);

    static byte[] nativeKey() {
        return nativeKey;
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
        ShieldMetrics.watchFirstFrame(activity);
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
            List<ShieldRules.Match> matches =
                    active.scanApk(context.getApplicationInfo().sourceDir);
            for (ShieldRules.Match match : matches) {
                try {
                    JSONObject payload = new JSONObject();
                    payload.put("entry", match.entry);
                    ShieldEvents.record("rule_hit", match.ruleId, 0.7,
                            match.sha256, payload);
                } catch (Exception error) {
                    Log.w(TAG, "event record failed: " + error);
                }
            }
            ruleMatchCount = matches.size();
            Log.i(TAG, "rule scan done matches=" + matches.size()
                    + " ms=" + (SystemClock.elapsedRealtime() - started));
        }, "shield-rule-scan");
        thread.setDaemon(true);
        thread.start();
    }

    public static int getRuleMatchCount() {
        return ruleMatchCount;
    }

    public static String auditSummary() {
        ShieldConfig active = config;
        StringBuilder out = new StringBuilder();
        out.append("== 壳与构建 ==\n");
        boolean failed = state == STATE_RECOVERY;
        out.append(mark(failed ? '✗' : (state >= STATE_APP_ATTACHED ? '✓' : '!'),
                "运行阶段", stateName(state)
                        + (failure.isEmpty() ? "" : " · " + failure)));
        if (active != null) {
            out.append(mark('✓', "壳版本", active.shellVersion));
            out.append(mark('✓', "构建 ID", active.buildId));
        }
        out.append("== 保护层 ==\n");
        if (active != null) {
            String keyMode;
            if (active.key == null || active.key.isEmpty()) {
                keyMode = "授权服务";
            } else if (active.key.endsWith(".wb")) {
                keyMode = "白盒（native）";
            } else {
                keyMode = "内置明文";
            }
            out.append(mark('✓', "内容密钥", keyMode));
            out.append(mark('✓', "核心库",
                    active.core.isEmpty() ? "明文" : "已加密"));
            out.append(mark(active.detection ? '✓' : '✗', "运行时检测",
                    active.detection ? "开启" : "关闭"));
            out.append(mark('✓', "处置策略", active.response));
            out.append(mark('✓', "规则包", "v" + active.rulesVersion
                    + " · cert " + (active.certSha256.isEmpty() ? "-"
                            : active.certSha256.substring(0, 12))));
        }
        out.append(mark(ShieldNativeFileHook.installed() ? '✓' : '✗',
                "Native Hook", ShieldNativeFileHook.installed() ? "已安装" : "不可用"));
        out.append("== 加载 ==\n");
        out.append(mark('✓', "内存 DEX", dexCount + " 个 · 解密 " + decryptMs + " ms"));
        out.append(mark('✓', "ART 环境", ShieldArt.describe()));
        out.append(mark('✓', "自研 Core", describe() + " · abi=" + abiVersion()));
        out.append("== 检测结果 ==\n");
        List<String> detections = ShieldDetect.summary();
        boolean none = detections.size() == 1 && "none".equals(detections.get(0));
        out.append(mark(none ? '✓' : '!', "运行时发现",
                none ? "0 项" : detections.size() + " 项命中"));
        if (!none) {
            for (String item : detections) {
                out.append("        · ").append(item).append('\n');
            }
        }
        out.append(mark(ruleMatchCount > 0 ? '!' : '✓', "规则命中",
                ruleMatchCount + " 条"));
        return out.toString();
    }

    private static String mark(char status, String label, String value) {
        return "[" + status + "] " + label + "  " + value + "\n";
    }

    private static String stateName(int value) {
        switch (value) {
            case STATE_VERIFIED:
                return "verified";
            case STATE_KEY_READY:
                return "key-ready";
            case STATE_DEX_READY:
                return "dex-ready";
            case STATE_APP_ATTACHED:
                return "app-attached";
            case STATE_RUNNING:
                return "running";
            case STATE_RECOVERY:
                return "recovery";
            default:
                return "uninitialized";
        }
    }

    public static void markRunning() {
        if (state == STATE_APP_ATTACHED) {
            state = STATE_RUNNING;
        }
    }

    private static native int nativeBootstrap();

    private static native int nativeBootstrapWithCore(int fd);

    public static native int abiVersion();

    public static native String describe();
}
