package dev.forgemirror.shield;

import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runtime environment checks. Findings are recorded as events and surfaced
 * through the configured response (default: a toast); nothing is killed.
 */
final class ShieldDetect {
    private static final String TAG = "ShieldDetect";
    private static final long MAX_MAPS_BYTES = 8L << 20;
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static final AtomicBoolean DEBUGGER_REPORTED = new AtomicBoolean();

    private ShieldDetect() {
    }

    static final class Finding {
        final String ruleId;
        final String kind;
        final String evidence;
        final double confidence;

        Finding(String ruleId, String kind, String evidence, double confidence) {
            this.ruleId = ruleId;
            this.kind = kind;
            this.evidence = evidence;
            this.confidence = confidence;
        }
    }

    static void start(Context context, ShieldConfig config) {
        if (!STARTED.compareAndSet(false, true)) {
            return;
        }
        if (!ShieldServerConfig.detectionEnabled(context, config.detection)) {
            Log.i(TAG, "detection disabled");
            return;
        }
        Thread thread = new Thread(() -> {
            List<Finding> findings = scan(context);
            if (findings.isEmpty()) {
                Log.i(TAG, "no runtime findings");
                return;
            }
            if (!ShieldProcess.isMain(context)) {
                ShieldDetectionBridge.send(context, findings);
                return;
            }
            for (Finding finding : findings) {
                try {
                    JSONObject payload = new JSONObject();
                    payload.put("kind", finding.kind);
                    payload.put("evidence", finding.evidence);
                    ShieldEvents.record("runtime_detection", finding.ruleId,
                            finding.confidence, sha256(finding.evidence), payload);
                } catch (Exception error) {
                    Log.w(TAG, "finding record failed: " + error);
                }
            }
            ShieldResponse.dispatch(context, findings,
                    ShieldServerConfig.response(context, config.response));
            for (Finding finding : findings) {
                if ("env_debugger".equals(finding.ruleId)) {
                    DEBUGGER_REPORTED.set(true);
                }
            }
            if (ShieldProcess.isMain(context)) {
                startDebuggerWatchdog(context, config);
            }
        }, "shield-detect");
        thread.setDaemon(true);
        thread.start();
    }

    private static List<Finding> scan(Context context) {
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        scanMaps(findings, seen);
        scanThreads(findings, seen);
        scanDebugger(findings, seen);
        scanRoot(findings, seen);
        scanEmulator(findings, seen);
        scanXposedClass(findings, seen);
        scanKnownPaths(findings, seen);
        scanFridaPorts(findings, seen);
        scanFridaProcesses(findings, seen);
        return findings;
    }

    static String classifyMapsLine(String line) {
        if (line == null) {
            return null;
        }
        String lower = line.toLowerCase(Locale.US);
        if (lower.contains("libshield") || lower.contains("libshadowhook")
                || lower.contains("shadowhook") || lower.contains("libyara")
                || lower.contains("forgemirror")) {
            return null;
        }
        if (containsAny(lower, "frida", "gum-js", "frida-gadget", "linjector")) {
            return "env_frida";
        }
        if (containsAny(lower, "xposed", "lsposed", "edxposed", "dexposed")) {
            return "env_xposed";
        }
        if (containsAny(lower, "zygisk", "riru", "magisk", "substrate",
                "adbi", "ddi", "taichi", "roothide")) {
            return "env_injection";
        }
        if (containsAny(lower, "youpk", "fupk", "fart", "dumpdex", "yarfahook",
                "dumpartmethod", "dumpdexfilebyartmethod")) {
            return "env_unpacker";
        }
        if (containsAny(lower, "libhook", "inlinehook", "bhook", "dobby",
                "shadowhook") && !lower.contains("libc++")) {
            return "env_hook";
        }
        return null;
    }

    static String kindForRule(String ruleId) {
        switch (ruleId) {
            case "env_frida":
                return "frida";
            case "env_xposed":
                return "xposed";
            case "env_injection":
                return "injection";
            case "env_unpacker":
                return "unpacker";
            case "env_hook":
                return "hook";
            default:
                return "unknown";
        }
    }

    static double confidenceForRule(String ruleId) {
        switch (ruleId) {
            case "env_frida":
            case "env_xposed":
                return 0.9;
            case "env_injection":
                return 0.8;
            case "env_unpacker":
                return 0.75;
            case "env_hook":
                return 0.6;
            default:
                return 0.5;
        }
    }

    static String classifyThread(String name) {
        if (name == null) {
            return null;
        }
        String lower = name.toLowerCase(Locale.US);
        if (containsAny(lower, "gum-js-loop", "gmain", "pool-frida")) {
            return "env_frida";
        }
        return null;
    }

    static String classifyBuild(String fingerprint, String model,
                                String hardware, String product) {
        String combined = safe(fingerprint).toLowerCase(Locale.US) + "|"
                + safe(model).toLowerCase(Locale.US) + "|"
                + safe(hardware).toLowerCase(Locale.US) + "|"
                + safe(product).toLowerCase(Locale.US);
        if (containsAny(combined, "generic", "emulator", "sdk_gphone", "google_sdk",
                "vbox", "genymotion", "goldfish", "ranchu")) {
            return "env_emulator";
        }
        return null;
    }

    static String classifyKnownPath(String path) {
        if (path == null) {
            return null;
        }
        String lower = path.toLowerCase(Locale.US);
        if (lower.contains("frida-server") || lower.contains("frida-server-")) {
            return "env_frida";
        }
        if (lower.contains("/zygisk") || lower.contains("zygisk_")
                || lower.contains("/riru") || lower.contains("/system/bin/.ext")
                || lower.contains("/data/local/xbin") || lower.contains("/system/sd/xbin")) {
            return "env_injection";
        }
        if (lower.contains("youpk") || lower.contains("fupk") || lower.contains("fart")) {
            return "env_unpacker";
        }
        return null;
    }

    static String classifyTcpLine(String line) {
        if (line == null || line.startsWith("sl")) {
            return null;
        }
        String[] fields = line.trim().split("\\s+");
        if (fields.length < 2 || !fields[1].contains(":")) {
            return null;
        }
        String local = fields[1];
        String port = local.substring(local.lastIndexOf(':') + 1).toLowerCase(Locale.US);
        if ("69a2".equals(port) || "69a3".equals(port)) {
            return "env_frida";
        }
        return null;
    }

    private static void scanKnownPaths(List<Finding> findings, Set<String> seen) {
        String[] paths = {
                "/data/local/tmp/frida-server",
                "/data/local/tmp/frida-server-16",
                "/data/local/tmp/frida-server-17",
                "/data/adb/modules/zygisk",
                "/data/adb/modules/zygisk_zygisk",
                "/data/adb/modules/riru",
                "/system/bin/.ext",
                "/data/local/xbin",
                "/system/sd/xbin",
                "/data/local/bin",
        };
        for (String path : paths) {
            String rule = classifyKnownPath(path);
            if (rule != null && new File(path).exists()) {
                add(findings, seen, rule, kindForRule(rule), path,
                        confidenceForRule(rule));
            }
        }
    }

    private static void scanFridaPorts(List<Finding> findings, Set<String> seen) {
        String[] files = {"/proc/net/tcp", "/proc/net/tcp6"};
        for (String name : files) {
            File file = new File(name);
            if (!file.isFile()) {
                continue;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (classifyTcpLine(line) != null) {
                        add(findings, seen, "env_frida", "frida",
                                name + ":27042/27043", 0.7);
                        break;
                    }
                }
            } catch (Exception ignored) {
                // Not readable.
            }
        }
    }

    private static void scanFridaProcesses(List<Finding> findings, Set<String> seen) {
        File proc = new File("/proc");
        File[] entries = proc.listFiles();
        if (entries == null) {
            return;
        }
        int visited = 0;
        for (File entry : entries) {
            if (visited++ > 256) {
                break;
            }
            String name = entry.getName();
            if (!name.matches("\\d+")) {
                continue;
            }
            File cmdline = new File(entry, "cmdline");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(cmdline), StandardCharsets.UTF_8))) {
                String command = reader.readLine();
                if (command != null && command.toLowerCase(Locale.US).contains("frida")) {
                    add(findings, seen, "env_frida", "frida",
                            "process:" + command.trim(), 0.8);
                }
            } catch (Exception ignored) {
                // Permission denied for other UIDs.
            }
        }
    }

    private static void startDebuggerWatchdog(Context context, ShieldConfig config) {
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    return;
                }
                boolean attached = Debug.isDebuggerConnected() || Debug.waitingForDebugger();
                int tracer = tracerPid();
                if (!attached && tracer <= 0) {
                    continue;
                }
                if (!DEBUGGER_REPORTED.compareAndSet(false, true)) {
                    continue;
                }
                List<Finding> findings = new ArrayList<>();
                findings.add(new Finding("env_debugger", "debugger",
                        attached ? "DebuggerConnected" : "TracerPid>0", 0.9));
                try {
                    JSONObject payload = new JSONObject();
                    payload.put("kind", "debugger");
                    payload.put("evidence", findings.get(0).evidence);
                    ShieldEvents.record("runtime_detection", "env_debugger", 0.9,
                            sha256(findings.get(0).evidence), payload);
                } catch (Exception error) {
                    Log.w(TAG, "watchdog record failed: " + error);
                }
                ShieldResponse.dispatch(context, findings,
                        ShieldServerConfig.response(context, config.response));
            }
        }, "shield-debug-watch");
        thread.setDaemon(true);
        thread.start();
    }

    private static void scanMaps(List<Finding> findings, Set<String> seen) {
        File maps = new File("/proc/self/maps");
        if (!maps.isFile()) {
            return;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(maps), StandardCharsets.UTF_8))) {
            String line;
            long budget = MAX_MAPS_BYTES;
            while ((line = reader.readLine()) != null) {
                budget -= line.length() + 1L;
                if (budget <= 0) {
                    break;
                }
                String ruleId = classifyMapsLine(line);
                if (ruleId == null) {
                    continue;
                }
                String path = pathOf(line);
                add(findings, seen, ruleId, kindForRule(ruleId),
                        path != null ? path : line.trim(),
                        confidenceForRule(ruleId));
            }
        } catch (Exception error) {
            Log.w(TAG, "maps scan failed: " + error);
        }
    }

    private static void scanThreads(List<Finding> findings, Set<String> seen) {
        File tasks = new File("/proc/self/task");
        File[] entries = tasks.listFiles();
        if (entries == null) {
            return;
        }
        for (File entry : entries) {
            File comm = new File(entry, "comm");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(comm), StandardCharsets.UTF_8))) {
                String name = reader.readLine();
                if (name == null) {
                    continue;
                }
                if (classifyThread(name) != null) {
                    add(findings, seen, "env_frida", "frida",
                            "thread:" + name, 0.85);
                }
            } catch (Exception ignored) {
                // Thread may exit while scanning.
            }
        }
    }

    private static void scanDebugger(List<Finding> findings, Set<String> seen) {
        boolean attached = Debug.isDebuggerConnected() || Debug.waitingForDebugger();
        int tracer = tracerPid();
        if (attached || tracer > 0) {
            add(findings, seen, "env_debugger", "debugger",
                    attached ? "DebuggerConnected" : "TracerPid>0", 0.9);
        }
    }

    private static int tracerPid() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream("/proc/self/status"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String value = line.substring("TracerPid:".length()).trim();
                    return Integer.parseInt(value);
                }
            }
        } catch (Exception ignored) {
            // Not available.
        }
        return 0;
    }

    private static void scanRoot(List<Finding> findings, Set<String> seen) {
        String[] paths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
                "/data/adb/magisk", "/data/adb/modules", "/system/app/Superuser.apk",
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                add(findings, seen, "env_root", "root", path, 0.7);
                return;
            }
        }
        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            add(findings, seen, "env_root", "root", "Build.TAGS=test-keys", 0.5);
        }
    }

    private static void scanEmulator(List<Finding> findings, Set<String> seen) {
        String ruleId = classifyBuild(Build.FINGERPRINT, Build.MODEL,
                Build.HARDWARE, Build.PRODUCT);
        if (ruleId != null) {
            add(findings, seen, ruleId, "emulator",
                    "Build=" + Build.FINGERPRINT, 0.5);
            return;
        }
        if (new File("/dev/qemu_pipe").exists()
                || new File("/dev/goldfish_pipe").exists()) {
            add(findings, seen, "env_emulator", "emulator", "qemu device", 0.6);
        }
    }

    private static void scanXposedClass(List<Finding> findings, Set<String> seen) {
        String[] classes = {
                "de.robv.android.xposed.XposedBridge",
                "org.lsposed.lspd.core.Main",
                "com.elderdrivers.riru.edxp.core.Main",
        };
        for (String name : classes) {
            try {
                Class.forName(name, false, ShieldDetect.class.getClassLoader());
                add(findings, seen, "env_xposed", "xposed", "class:" + name, 0.8);
            } catch (Throwable ignored) {
                // Not present.
            }
        }
    }

    private static void add(List<Finding> findings, Set<String> seen,
                            String ruleId, String kind, String evidence,
                            double confidence) {
        String key = ruleId + "|" + evidence;
        if (!seen.add(key)) {
            return;
        }
        findings.add(new Finding(ruleId, kind, evidence, confidence));
        Log.w(TAG, "finding " + ruleId + " " + evidence);
    }

    private static String pathOf(String line) {
        int slash = line.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String path = line.substring(slash).trim();
        return path.isEmpty() ? null : path;
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    static String hash(String value) {
        return sha256(value);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                builder.append(String.format(Locale.US, "%02x", item & 0xff));
            }
            return builder.toString();
        } catch (Exception error) {
            return "";
        }
    }
}
